use std::collections::HashMap;

use crate::{
    block::{Block, BlockHeader},
    error::{ChainError, TxError},
    transaction::Transaction,
    wallet::Address,
};

/// Cache of current balances and next transaction nonce for each `Address` on the `BlockChain`.
#[derive(Debug, Clone, Default)]
struct State {
    balances: HashMap<Address, u64>,
    nonces: HashMap<Address, u64>,
}

/// A proof of work chain of blocks, with a mempool of transactions waiting to
/// be mined into the next one.
#[derive(Debug, Clone)]
pub struct Blockchain {
    blocks: Vec<Block>,
    state: State,
    /// Mempool of transactions waiting to be recorded in a `Block`.
    pending: Vec<Transaction>,
    difficulty: u32,
    mining_reward: u64,
}

impl Blockchain {
    /// Creates a chain holding nothing but a freshly mined genesis block.
    pub fn new(difficulty: u32, mining_reward: u64) -> Self {
        let genesis = Block::genesis(difficulty);

        Self {
            blocks: vec![genesis],
            state: State::default(),
            pending: Vec::new(),
            difficulty,
            mining_reward,
        }
    }

    /// Returns the header of every block in the chain.
    pub fn headers(&self) -> Vec<BlockHeader> {
        self.blocks.iter().map(|b| b.header()).collect()
    }

    /// Returns every block in the chain, from genesis onwards.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Returns the number of leading zero bits a block hash must have.
    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    /// Returns the mempool of transactions waiting to be mined.
    pub fn pending(&self) -> &[Transaction] {
        &self.pending
    }

    /// Returns the most recently mined block.
    pub fn last_block(&self) -> &Block {
        self.blocks
            .last()
            .expect("chain always has a genesis block")
    }

    /// Returns the balance `address` holds across mined blocks, ignoring the
    /// mempool.
    pub fn balance_of(&self, address: &Address) -> u64 {
        self.state.balances.get(address).copied().unwrap_or(0)
    }

    /// Returns the nonce `address` must use for its next `Transaction`,
    /// counting both mined and pending transactions it has sent.
    pub fn next_nonce(&self, address: &Address) -> u64 {
        let mined = self.state.nonces.get(address).copied().unwrap_or(0);
        let pending = self.pending.iter().filter(|tx| tx.sent_by(address)).count() as u64;

        mined + pending
    }

    /// Queues `tx` to the mempool once it passes every admission rule.
    ///
    /// # Errors
    /// Returns a `TxError` if the signature does not verify, the transaction
    /// mints coin, the amount is zero, the nonce is not the one expected next,
    /// or the sender's spendable balance falls short.
    pub fn queue_tx(&mut self, tx: Transaction) -> Result<(), TxError> {
        // verify tx sender
        tx.verify_transfer()?;

        let Some(from) = tx.sender() else {
            return Err(TxError::MintingNotAllowed);
        };

        if tx.amount() == 0 {
            return Err(TxError::ZeroAmount);
        }

        // nonce prevents a replay attack where an attacker
        // re-broadcasts an accepted transaction to the mempool
        let expected = self.next_nonce(&from);
        if tx.nonce() != expected {
            return Err(TxError::WrongNonce {
                expected,
                got: tx.nonce(),
            });
        }

        // ensure sender is not overspending
        let available = self.spendable_balance(&from);

        if available < tx.amount() {
            return Err(TxError::InsufficientFunds {
                available,
                requested: tx.amount(),
            });
        }

        self.pending.push(tx);
        Ok(())
    }

    /// Mines every pending transaction into a new block that pays `miner` the
    /// mining reward, and returns that block.
    pub fn mine_pending(&mut self, miner: &Address) -> &Block {
        // moves ownership and replace with empty vec in one step
        let mut txs: Vec<Transaction> = std::mem::take(&mut self.pending);
        let height = self.last_block().height() + 1;

        // it does not matter if there are no pending transactions
        // miners are paid for the work put into finding a valid pow

        // reward tx always first tx in a block
        txs.insert(0, Transaction::reward(*miner, self.mining_reward, height));

        // update balance and nonce cache for all parties in the block's txs
        for tx in txs.iter() {
            Self::update_balances(&mut self.state.balances, tx)
                .expect("blockchain invariant: queued transactions are always payable");

            // update nonce for sender's next tx
            if let Some(sender) = tx.sender() {
                *self.state.nonces.entry(sender).or_default() += 1;
            }
        }

        // mine new block
        let block = Block::new(self.last_block(), txs, self.difficulty);
        self.blocks.push(block);

        self.last_block()
    }

    /// Returns the balance left to `address` once its pending outgoing
    /// transactions are covered.
    ///
    /// Pending funds owed *to* `address` do not count towards this.
    pub fn spendable_balance(&self, address: &Address) -> u64 {
        let pending_out: u64 = self
            .pending
            .iter()
            .filter(|tx| tx.sent_by(address))
            .map(|tx| tx.amount())
            .sum();

        self.balance_of(address).saturating_sub(pending_out)
    }

    /// Applies `tx` to `balances` in place.
    ///
    /// # Errors
    /// Returns `TxError::InsufficientFunds` if the sender cannot cover the
    /// transfer.
    fn update_balances(
        balances: &mut HashMap<Address, u64>,
        tx: &Transaction,
    ) -> Result<(), TxError> {
        // None for reward tx only
        if let Some(from) = tx.sender() {
            let balance = balances.entry(from).or_default();

            // decrement sender's balance if available
            *balance = balance
                .checked_sub(tx.amount())
                .ok_or(TxError::InsufficientFunds {
                    available: *balance,
                    requested: tx.amount(),
                })?
        }

        // increment receiver's balance
        // this path handles rewards as well
        *balances.entry(tx.to()).or_default() += tx.amount();

        Ok(())
    }

    /// Replays the whole chain from genesis, verifying its structural and
    /// transaction integrity.
    ///
    /// # Errors
    /// Returns a `ChainError` naming the first block that breaks a structural
    /// rule, or the first transaction that breaks a ledger rule.
    pub fn validate(&self) -> Result<(), ChainError> {
        //? NOTE: we still build balances and nonces maps here
        //? because we must verify chain independently of the cache state
        // tracks transaction nonces to ensure incremental nonces
        let mut nonces: HashMap<Address, u64> = HashMap::new();
        // tracks the latest available balance per address
        let mut balances: HashMap<Address, u64> = HashMap::new();

        for (pos, block) in self.blocks.iter().enumerate() {
            let height = block.height();

            // ============= BLOCK LEVEL VERIFICATION =============

            // block heights must increase by 1
            if height != pos as u64 {
                return Err(ChainError::WrongHeight(block.height()));
            }
            // block hash must meet difficulty
            if !block.has_valid_hash(self.difficulty) {
                return Err(ChainError::BrokenHash(block.height()));
            }

            // block root must cover all its txs
            if !block.has_valid_root() {
                return Err(ChainError::BrokenRoot(block.height()));
            }

            // hash link between two contiguous blocks must be preserved
            if pos > 0 && block.prev_hash() != self.blocks[pos - 1].hash {
                return Err(ChainError::BrokenLink(block.height()));
            }

            // a valid block start with a reward tx
            if pos > 0 {
                match block.txs().first() {
                    Some(tx) if tx.is_reward() => {
                        if tx.amount() != self.mining_reward {
                            return Err(ChainError::BadTransaction {
                                height,
                                slot: 0,
                                cause: TxError::WrongReward {
                                    expected: self.mining_reward,
                                    got: tx.amount(),
                                },
                            });
                        };
                    }
                    _ => return Err(ChainError::MissingReward(height)),
                }
            }

            // ============= TRANSACTION LEVEL VERIFICATION =============

            for (slot, tx) in block.txs().iter().enumerate() {
                // verify sign in transaction
                if let Some(err) = tx.verify_transfer().err() {
                    return Err(ChainError::BadTransaction {
                        height,
                        slot,
                        cause: err,
                    });
                }

                // the only reward allowed is the one at slot 0 of a mined
                // block, and the block level check above already vetted it
                if tx.is_reward() && (pos == 0 || slot > 0) {
                    return Err(ChainError::BadTransaction {
                        height,
                        slot,
                        cause: TxError::UnexpectedReward,
                    });
                }

                if let Some(from) = tx.sender() {
                    // track sender's transaction count
                    let expected = nonces.entry(from).or_default();
                    if tx.nonce() != *expected {
                        return Err(ChainError::BadTransaction {
                            height,
                            slot,
                            cause: TxError::WrongNonce {
                                expected: *expected,
                                got: tx.nonce(),
                            },
                        });
                    }

                    *expected += 1;
                }

                // apply the transfer to the running ledger; this path also
                // credits rewards, which fund every later transaction
                Self::update_balances(&mut balances, tx).map_err(|cause| {
                    ChainError::BadTransaction {
                        height,
                        slot,
                        cause,
                    }
                })?;
            }
        }

        Ok(())
    }

    /// Returns `true` if `validate` finds no fault in the chain.
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::meets_difficulty;
    use crate::wallet::Wallet;

    fn chain() -> Blockchain {
        Blockchain::new(8, 50)
    }

    fn signed(from: &Wallet, to: &Wallet, amount: u64, nonce: u64) -> Transaction {
        Transaction::transfer(from, to.address(), amount, nonce)
    }

    #[test]
    fn genesis_block_exists_and_is_mined() {
        let chain = chain();

        assert_eq!(chain.blocks().len(), 1);
        assert_eq!(chain.last_block().height(), 0);
        assert!(meets_difficulty(
            &chain.last_block().hash,
            chain.difficulty()
        ))
    }

    #[test]
    fn mining_pays_miner_and_clears_pool() {
        let mut chain = chain();
        let miner = Wallet::from_seed("alice");

        chain.mine_pending(&miner.address());

        assert!(chain.pending().is_empty());
        assert_eq!(chain.balance_of(&miner.address()), chain.mining_reward);
        assert!(chain.is_valid());
    }

    #[test]
    fn transfers_move_amount_between_addresses() {
        let mut chain = chain();

        let sender = Wallet::from_seed("alice");
        let receiver = Wallet::from_seed("bob");
        let miner = Wallet::from_seed("carol");

        let amount = 20;

        chain.mine_pending(&sender.address());

        chain
            .queue_tx(signed(&sender, &receiver, amount, 0))
            .unwrap();

        chain.mine_pending(&miner.address());

        assert_eq!(
            chain.balance_of(&sender.address()),
            chain.mining_reward - amount
        );
        assert_eq!(chain.balance_of(&receiver.address()), amount);
        assert_eq!(chain.balance_of(&miner.address()), chain.mining_reward);
        assert!(chain.is_valid());
    }

    #[test]
    fn overspending_is_rejected() {
        let mut chain = chain();

        let sender = Wallet::from_seed("alice");
        let receiver = Wallet::from_seed("bob");
        let amount = 100;

        let result = chain.queue_tx(signed(&sender, &receiver, amount, 0));

        assert_eq!(
            result,
            Err(TxError::InsufficientFunds {
                available: 0,
                requested: amount
            })
        );
    }

    #[test]
    fn pending_transactions_reduce_spendable_balance() {
        let mut chain = chain();

        let sender = Wallet::from_seed("alice");
        let receiver = Wallet::from_seed("bob");
        let amount = 20;

        chain.mine_pending(&sender.address());

        chain
            .queue_tx(signed(&sender, &receiver, amount, 0))
            .unwrap();

        assert_eq!(
            chain.spendable_balance(&sender.address()),
            chain.mining_reward - amount
        );

        // the queued transfer is already spoken for, so the rest of the
        // balance is all that is left to spend
        assert!(
            chain
                .queue_tx(signed(&sender, &receiver, 100_000, 1))
                .is_err()
        );
    }

    #[test]
    fn tampering_with_block_tx_breaks_root() {
        let mut chain = chain();

        let sender = Wallet::from_seed("alice");

        chain.mine_pending(&sender.address());

        // tampering: sheinbase -> sender : 9999 (instead of 50)
        chain.blocks[1].txs_mut()[0] = Transaction::reward(sender.address(), 9_999, 1);
        // the header is untouched, so its own hash still stands
        assert!(chain.blocks[1].has_valid_hash(chain.difficulty));
        assert!(!chain.blocks[1].has_valid_root());

        // block's merkle root does not cover the tampered transaction
        assert_eq!(chain.validate(), Err(ChainError::BrokenRoot(1)));
    }

    #[test]
    fn remining_tampered_block_breaks_next_link() {
        let mut chain = chain();
        let sender = Wallet::from_seed("alice");
        let receiver = Wallet::from_seed("bob");

        chain.mine_pending(&sender.address()); // alice should get 50
        chain.mine_pending(&receiver.address()); // bob should get 50

        // chain: block 0 (genesis) -> block 1 -> block 2
        assert!(chain.is_valid());

        // tamper with block 1, then re-mine it to find a valid hash
        *chain.blocks[1].timestamp_mut() += 3_600;
        chain.blocks[1].mine(chain.difficulty);

        // attacker needs to re-mine block 2 as well for chain to be valid
        assert_eq!(chain.validate(), Err(ChainError::BrokenLink(2)));
    }

    #[test]
    fn rewriting_the_whole_chain_is_caught_by_the_rules() {
        let mut chain = chain();
        let sender = Wallet::from_seed("alice");
        let receiver = Wallet::from_seed("bob");

        chain.mine_pending(&sender.address());
        chain.mine_pending(&receiver.address());

        chain.blocks[1].txs_mut()[0] = Transaction::reward(sender.address(), 9_999, 1);
        for height in 1..chain.blocks.len() {
            let prev_hash = chain.blocks[height - 1].hash;
            *chain.blocks[height].prev_hash_mut() = prev_hash;
            chain.blocks[height].mine(chain.difficulty);
        }

        assert_eq!(
            chain.validate(),
            Err(ChainError::BadTransaction {
                height: 1,
                slot: 0,
                cause: TxError::WrongReward {
                    expected: 50,
                    got: 9_999
                }
            })
        );
    }

    #[test]
    fn cached_state_matches_full_replay() {
        let mut chain = chain();

        let sender = Wallet::from_seed("vihanga");
        let receiver = Wallet::from_seed("meowsies");
        let miner = Wallet::from_seed("mr.miner");

        chain.mine_pending(&sender.address());

        for _ in 0..3 {
            let nonce = chain.next_nonce(&sender.address());
            chain
                .queue_tx(signed(&sender, &receiver, 10, nonce))
                .unwrap();
        }
        chain.mine_pending(&miner.address());

        let nonce = chain.next_nonce(&receiver.address());
        chain
            .queue_tx(signed(&receiver, &sender, 10, nonce))
            .unwrap();
        chain.mine_pending(&miner.address());

        assert!(chain.validate().is_ok());

        let mut balances: HashMap<Address, u64> = HashMap::new();
        let mut nonces: HashMap<Address, u64> = HashMap::new();

        for block in chain.blocks() {
            for tx in block.txs() {
                Blockchain::update_balances(&mut balances, tx).unwrap();
                if let Some(from) = tx.sender() {
                    *nonces.entry(from).or_default() += 1;
                }
            }
        }

        for addr in [sender.address(), receiver.address(), miner.address()] {
            assert_eq!(
                chain.balance_of(&addr),
                balances.get(&addr).copied().unwrap_or(0)
            );
            assert_eq!(
                chain.next_nonce(&addr),
                nonces.get(&addr).copied().unwrap_or(0)
            );
        }

        assert_eq!(chain.balance_of(&sender.address()), 30);
        assert_eq!(chain.balance_of(&receiver.address()), 20);
        assert_eq!(chain.balance_of(&miner.address()), 100);
        assert_eq!(chain.next_nonce(&sender.address()), 3);
        assert_eq!(chain.next_nonce(&receiver.address()), 1);
        assert_eq!(chain.next_nonce(&miner.address()), 0);
    }
}
