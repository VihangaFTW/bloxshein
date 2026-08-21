use crate::{block::Block, error::ChainError, transaction::Transaction};

#[derive(Debug, Clone, PartialEq)]
enum InvalidChain {
    WrongIndex(u64),
    BrokenHash(u64),
    BrokenLink(u64),
}

#[derive(Debug, Clone)]
pub struct Blockchain {
    blocks: Vec<Block>,
    /// Mempool of transactions waiting to be recorded in a `Block`.
    pending: Vec<Transaction>,
    difficulty: u32,
    mining_reward: u64,
}

impl Blockchain {
    pub fn new(difficulty: u32, mining_reward: u64) -> Self {
        let mut genesis = Block::genesis();
        genesis.mine(difficulty);

        Self {
            blocks: vec![genesis],
            pending: Vec::new(),
            difficulty,
            mining_reward,
        }
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    pub fn pending(&self) -> &[Transaction] {
        &self.pending
    }

    pub fn last_block(&self) -> &Block {
        self.blocks
            .last()
            .expect("chain always has a genesis block")
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), ChainError> {
        if tx.from.trim().is_empty() || tx.to.trim().is_empty() {
            return Err(ChainError::EmptyAddress);
        }

        if tx.amount == 0 {
            return Err(ChainError::ZeroAmount);
        }

        if tx.from == tx.to {
            return Err(ChainError::SelfTransfer);
        }

        if !tx.is_reward() {
            let available = self.spendable_balance(&tx.from);

            if available < tx.amount {
                return Err(ChainError::InsufficientFunds {
                    available,
                    requested: tx.amount,
                });
            }
        }

        self.pending.push(tx);
        Ok(())
    }

    /// Delegates all pending transactions in the chain to a miner and returns the resulting `Block`.
    pub fn mine_pending(&mut self, miner: &str) -> &Block {
        // moves ownership and replace with empty vec in one step
        let mut txs: Vec<Transaction> = std::mem::take(&mut self.pending);

        // it does not matter if there are no pending transactions
        // miners are paid for the work put into finding a valid nonce

        // reward tx always first tx in a block
        txs.push(Transaction::reward(miner, self.mining_reward));

        // mine new block
        let mut block = Block::new(self.last_block(), txs);
        block.mine(self.difficulty);
        self.blocks.push(block);

        self.last_block()
    }

    pub fn balance_of(&self, address: &str) -> u64 {
        let mut balance: i128 = 0;

        for block in &self.blocks {
            for tx in &block.txs {
                if tx.from == address {
                    balance -= i128::from(tx.amount);
                }
                if tx.to == address {
                    balance += i128::from(tx.amount);
                }
            }
        }

        balance.max(0) as u64
    }

    /// Checks whether the sender has sufficient funds
    /// aftet their pending transactions are cleared.
    pub fn spendable_balance(&self, address: &str) -> u64 {
        let pending_out: u64 = self
            .pending
            .iter()
            .filter(|tx| tx.from == address)
            .map(|tx| tx.amount)
            .sum();

        self.balance_of(address).saturating_sub(pending_out)
    }

    fn validate(&self) -> Result<(), InvalidChain> {
        for (pos, block) in self.blocks.iter().enumerate() {
            // index must increase by 1
            if pos as u64 != block.index {
                return Err(InvalidChain::WrongIndex(block.index));
            }
            // block hash must meet difficulty
            if !block.has_valid_hash(self.difficulty) {
                return Err(InvalidChain::BrokenHash(block.index));
            }
            // hash link between two contiguous blocks must be preserved
            if pos > 0 && block.prev_hash != self.blocks[pos - 1].hash {
                return Err(InvalidChain::BrokenLink(block.index));
            }
        }

        // todo: check balances for each address

        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::meets_difficulty;

    fn chain() -> Blockchain {
        Blockchain::new(8, 50)
    }

    #[test]
    fn genesis_block_exists_and_is_mined() {
        let chain = chain();

        assert_eq!(chain.blocks().len(), 1);
        assert_eq!(chain.last_block().index, 0);
        assert!(meets_difficulty(
            &chain.last_block().hash,
            chain.difficulty()
        ))
    }

    #[test]
    fn mining_pays_miner_and_clears_pool() {
        let mut chain = chain();
        let miner = "alice";
        chain.mine_pending(miner);

        assert!(chain.pending().is_empty());
        assert_eq!(chain.balance_of(miner), chain.mining_reward);
    }

    #[test]
    fn tansfers_move_amount_between_addresses() {
        let mut chain = chain();

        let sender = "alice";
        let receiver = "bob";
        let miner = "carol";

        let amount = 20;

        chain.mine_pending(sender);

        chain
            .add_transaction(Transaction::new(sender, receiver, amount))
            .unwrap();

        chain.mine_pending(miner);

        assert_eq!(chain.balance_of(sender), chain.mining_reward - amount);
        assert_eq!(chain.balance_of(receiver), amount);
        assert_eq!(chain.balance_of(miner), chain.mining_reward);
    }

    #[test]
    fn overspending_is_rejected() {
        let mut chain = chain();

        let sender = "alice";
        let receiver = "bob";
        let amount = 100;

        let result = chain.add_transaction(Transaction::new(sender, receiver, amount));

        assert_eq!(
            result,
            Err(ChainError::InsufficientFunds {
                available: 0,
                requested: amount
            })
        );
    }

    #[test]
    fn pending_transactions_reduce_spendable_balance() {
        let mut chain = chain();

        let sender = "alice";
        let receiver = "bob";
        let amount = 20;

        chain.mine_pending(sender);

        chain
            .add_transaction(Transaction::new(sender, receiver, amount))
            .unwrap();

        assert_eq!(
            chain.spendable_balance(sender),
            chain.mining_reward - amount
        );

        assert!(
            chain
                .add_transaction(Transaction::new(sender, receiver, 100000))
                .is_err()
        );
    }

    #[test]
    fn tampering_with_block_tx_breaks_hash() {
        let mut chain = chain();

        let sender = "alice";

        chain.mine_pending(sender);

        // tampering: sheinbase -> sender : 9999 (instead of 50)
        chain.blocks[1].txs[0].amount = 9_999;
        // block's hash should not match with new hash post tamper
        assert_eq!(chain.blocks[1].has_valid_hash(chain.difficulty), false);
    }

    #[test]
    fn remining_tampered_block_breaks_next_link() {
        let mut chain = chain();
        let sender = "alice";
        let receiver = "bob";
        chain.mine_pending(sender); // alice should get 50
        chain.mine_pending(receiver); // bob should get 50

        // chain: block 0 (genesis) -> block 1 -> block 2

        // tamper transactions in block 1
        // such that alice gets 9999 instead of 50
        chain.blocks[1].txs[0].amount = 9_999;

        // re-mine tampered block 1 to find a valid hash
        chain.blocks[1].mine(chain.difficulty);

        // attacker needs to re-mine block 2 as well for chain to be valid
        assert_eq!(chain.validate(), Err(InvalidChain::BrokenLink(2)));
    }
}
