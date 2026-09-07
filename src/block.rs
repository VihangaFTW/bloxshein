use std::time::{SystemTime, UNIX_EPOCH};

use crate::merkle::{Hash, MerkleProof, MerkleTree, ZERO_HASH, hash_leaf, hash256, to_merkle_root};
use crate::transaction::Transaction;

/// The fields a block is hashed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    /// Height of the block in the chain, with genesis at 0.
    pub height: u64,
    /// Seconds since the Unix epoch at which the block was built.
    pub timestamp: u64,
    /// Hash of the preceding block, or `ZERO_HASH` for genesis.
    pub prev_hash: Hash,
    /// Merkle root built from the block's transactions.
    pub root: Hash,
    /// Nonce found by mining.
    pub pow: u64,
}

const HEADER_BYTES: usize = 8 + 8 + 32 + 32 + 8;

impl BlockHeader {
    /// Computes the hash over the header's fields.
    pub fn hash(&self) -> Hash {
        let mut buf = [0u8; HEADER_BYTES];

        buf[..8].copy_from_slice(&self.height.to_be_bytes());
        buf[8..16].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[16..48].copy_from_slice(&self.prev_hash);
        buf[48..80].copy_from_slice(&self.root);
        buf[80..].copy_from_slice(&self.pow.to_be_bytes());

        hash256(&buf)
    }

    pub fn verify_inclusion(&self, tx: &Transaction, proof: &MerkleProof) -> bool {
        proof.verify(hash_leaf(&tx.hash_bytes()), self.root)
    }

    pub fn has_valid_pow(&self, difficulty: u32) -> bool {
        meets_difficulty(&self.hash(), difficulty)
    }
}

/// A batch of transactions bound to its predecessor by hash and sealed by
/// proof of work.
#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    /// Transactions recorded in the block.
    ///
    /// Private because `root` commits to exactly this list: editing it
    /// without re-mining would leave the two disagreeing.
    txs: Vec<Transaction>,

    /// Hash covering the entire block content, including its root.
    pub hash: Hash,
}

impl Block {
    /// Mines a block holding `txs` at the height following `prev`, searching
    /// for a nonce whose hash carries at least `difficulty` leading zero bits.
    ///
    /// # Panics
    /// Panics if the system clock is set before the Unix epoch.
    pub fn new(prev: &Block, txs: Vec<Transaction>, difficulty: u32) -> Self {
        let header = BlockHeader {
            height: prev.header.height + 1,
            timestamp: now(),
            prev_hash: prev.hash,
            root: ZERO_HASH,
            pow: 0,
        };

        let mut block = Self {
            header,
            txs,
            hash: ZERO_HASH,
        };

        block.mine(difficulty);
        block
    }

    /// Mines the genesis block, the transactionless root of a chain.
    ///
    /// # Panics
    /// Panics if the system clock is set before the Unix epoch.
    pub fn genesis(difficulty: u32) -> Self {
        let header = BlockHeader {
            height: 0,
            timestamp: now(),
            prev_hash: ZERO_HASH,
            root: ZERO_HASH,
            pow: 0,
        };

        let mut genesis = Self {
            header,
            txs: Vec::new(),

            hash: ZERO_HASH,
        };

        genesis.mine(difficulty);
        genesis
    }

    /// Returns the block header.
    pub fn header(&self) -> BlockHeader {
        self.header
    }

    /// Returns the transactions recorded in the block.
    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }

    /// Returns the block's height in the chain.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Returns the Merkle root the block committed to when it was mined.
    pub fn root(&self) -> Hash {
        self.header.root
    }

    /// Returns the hash of the preceding block, or `ZERO_HASH` for genesis.
    pub fn prev_hash(&self) -> Hash {
        self.header.prev_hash
    }

    /// Returns the nonce found by mining.
    pub fn pow(&self) -> u64 {
        self.header.pow
    }

    #[cfg(test)]
    pub(crate) fn txs_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.txs
    }

    #[cfg(test)]
    pub(crate) fn timestamp_mut(&mut self) -> &mut u64 {
        &mut self.header.timestamp
    }

    #[cfg(test)]
    pub(crate) fn prev_hash_mut(&mut self) -> &mut Hash {
        &mut self.header.prev_hash
    }

    /// Computes the Merkle root over `txs`.
    ///
    /// Returns `ZERO_HASH` if `txs` is empty.
    pub fn tx_root(txs: &[Transaction]) -> Hash {
        // hash of a transaction becomes a leaf in the tree
        let leaves: Vec<Hash> = txs
            .iter()
            .map(|tx| hash_leaf(tx.hash_bytes().as_slice()))
            .collect();

        // calculate root
        to_merkle_root(leaves).unwrap_or(ZERO_HASH)
    }

    /// Rebuilds the Merkle tree over the block's transactions.
    ///
    /// Returns `None` for a block with no transactions.
    pub fn tree(&self) -> Option<MerkleTree> {
        if self.txs.is_empty() {
            return None;
        }

        let leaves = self
            .txs
            .iter()
            .map(|tx| hash_leaf(&tx.hash_bytes()))
            .collect();

        MerkleTree::new(leaves)
    }

    /// Constructs the Merkle proof that `tx` belongs to this block.
    ///
    /// Returns `None` if the block does not record `tx`.
    pub fn proof_for(&self, tx: &Transaction) -> Option<MerkleProof> {
        self.tree()?.proof(self.position_of(tx)?)
    }

    /// Seals the block: commits to its current transactions, then counts the
    /// nonce up until the header hashes to `difficulty` leading zero bits.
    pub(crate) fn mine(&mut self, difficulty: u32) {
        self.header.root = Self::tx_root(&self.txs);

        loop {
            self.hash = self.rehash();
            if meets_difficulty(&self.hash, difficulty) {
                break;
            }
            self.header.pow += 1;
        }
    }

    /// Recomputes the hash over the block's header.
    pub fn rehash(&self) -> Hash {
        self.header.hash()
    }

    /// Returns `true` if the sealed root still matches the transactions the
    /// block carries.
    pub fn has_valid_root(&self) -> bool {
        self.header.root == Self::tx_root(&self.txs)
    }

    /// Returns `true` if the stored hash both matches the header it claims to
    /// cover and meets `difficulty`.
    pub fn has_valid_hash(&self, difficulty: u32) -> bool {
        self.rehash() == self.hash && meets_difficulty(&self.hash, difficulty)
    }

    /// Returns `true` if the block records `tx`.
    pub fn contains(&self, tx: &Transaction) -> bool {
        self.position_of(tx).is_some()
    }

    /// Returns the slot `tx` occupies in the block, if it is there at all.
    pub fn position_of(&self, tx: &Transaction) -> Option<usize> {
        self.txs.iter().position(|recorded| recorded == tx)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .expect("system clock is before the Unix epoch")
}

/// Returns `true` if `hash` opens with at least `difficulty` zero bits.
pub fn meets_difficulty(hash: &Hash, difficulty: u32) -> bool {
    leading_zero_bits(hash) >= difficulty
}

fn leading_zero_bits(hash: &Hash) -> u32 {
    let mut count = 0;
    for byte in hash {
        count += byte.leading_zeros();
        // terminate at the first non zero byte
        // after counting its leading bits
        if *byte != 0 {
            break;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    const DIFFICULTY: u32 = 8;

    fn reward_to(seed: &str, amount: u64, height: u64) -> Transaction {
        Transaction::reward(Wallet::from_seed(seed).address(), amount, height)
    }

    fn rewards(n: u64) -> Vec<Transaction> {
        (0..n).map(|i| reward_to("alice", 50 + i, i)).collect()
    }

    fn mined(txs: Vec<Transaction>) -> (Block, Block) {
        let genesis = Block::genesis(DIFFICULTY);
        let block = Block::new(&genesis, txs, DIFFICULTY);

        (genesis, block)
    }

    #[test]
    fn genesis_carries_no_transactions_and_an_empty_root() {
        let genesis = Block::genesis(DIFFICULTY);

        assert_eq!(genesis.height(), 0);
        assert!(genesis.txs().is_empty());
        assert_eq!(genesis.root(), ZERO_HASH);
        assert_eq!(genesis.prev_hash(), ZERO_HASH);
        assert!(genesis.has_valid_root());
        assert!(genesis.has_valid_hash(DIFFICULTY));
    }

    #[test]
    fn tx_root_of_no_transactions_is_the_zero_hash() {
        assert_eq!(Block::tx_root(&[]), ZERO_HASH);
    }

    #[test]
    fn tx_root_covers_every_transaction() {
        let one = [reward_to("alice", 50, 1)];
        let two = [reward_to("alice", 50, 1), reward_to("bob", 50, 1)];

        assert_ne!(Block::tx_root(&one), Block::tx_root(&two));
    }

    #[test]
    fn tx_root_depends_on_the_order_of_transactions() {
        let (a, b) = (reward_to("alice", 50, 1), reward_to("bob", 50, 1));

        assert_ne!(
            Block::tx_root(&[a.clone(), b.clone()]),
            Block::tx_root(&[b, a])
        );
    }

    #[test]
    fn a_mined_block_links_to_its_parent_and_seals_its_transactions() {
        let (genesis, block) = mined(vec![reward_to("alice", 50, 1)]);

        assert_eq!(block.height(), 1);
        assert_eq!(block.prev_hash(), genesis.hash);
        assert_eq!(block.root(), Block::tx_root(block.txs()));
        assert!(block.has_valid_root());
        assert!(block.has_valid_hash(DIFFICULTY));
    }

    #[test]
    fn editing_transactions_breaks_the_root_but_not_the_header() {
        let (_, mut block) = mined(vec![reward_to("alice", 50, 1)]);

        block.txs_mut()[0] = reward_to("mallory", 50, 1);

        assert!(block.has_valid_hash(DIFFICULTY));
        assert!(!block.has_valid_root());
    }

    #[test]
    fn editing_the_header_breaks_its_hash_but_not_the_root() {
        let (_, mut block) = mined(vec![reward_to("alice", 50, 1)]);

        block.header.timestamp += 3_600;

        assert!(block.has_valid_root());
        assert!(!block.has_valid_hash(DIFFICULTY));
    }

    #[test]
    fn remining_reseals_an_edited_block() {
        let (_, mut block) = mined(vec![reward_to("alice", 50, 1)]);

        block.txs_mut()[0] = reward_to("mallory", 50, 1);
        block.mine(DIFFICULTY);

        // the block is internally consistent again; only its parent's hash,
        // held by the block that follows, can still give the edit away
        assert!(block.has_valid_root());
        assert!(block.has_valid_hash(DIFFICULTY));
    }

    #[test]
    fn difficulty_counts_leading_zero_bits() {
        let mut hash = ZERO_HASH;
        hash[0] = 0b0000_1111;

        // four zero bits, then a one
        assert!(meets_difficulty(&hash, 4));
        assert!(!meets_difficulty(&hash, 5));
    }

    #[test]
    fn a_block_knows_which_transactions_it_carries() {
        let txs = rewards(5);
        let outsider = reward_to("mallory", 9_999, 7);
        let (_, block) = mined(txs.clone());

        for (slot, tx) in txs.iter().enumerate() {
            assert!(block.contains(tx));
            assert_eq!(block.position_of(tx), Some(slot));
        }

        assert!(!block.contains(&outsider));
        assert_eq!(block.position_of(&outsider), None);
    }

    #[test]
    fn every_recorded_transaction_proves_itself_against_the_header() {
        let txs = rewards(9);
        let (_, block) = mined(txs.clone());

        for tx in &txs {
            let proof = block.proof_for(tx).expect("a recorded tx has a proof");

            assert!(block.header.verify_inclusion(tx, &proof));
        }
    }

    #[test]
    fn there_is_no_proof_for_a_transaction_the_block_never_carried() {
        let (_, block) = mined(rewards(4));

        assert_eq!(block.proof_for(&reward_to("mallory", 9_999, 7)), None);
    }

    #[test]
    fn a_proof_does_not_carry_over_to_another_transaction() {
        let txs = rewards(8);
        let (_, block) = mined(txs.clone());

        let proof = block.proof_for(&txs[2]).unwrap();

        assert!(block.header.verify_inclusion(&txs[2], &proof));
        assert!(!block.header.verify_inclusion(&txs[5], &proof));
    }

    #[test]
    fn a_proof_does_not_verify_against_another_blocks_header() {
        let genesis = Block::genesis(DIFFICULTY);
        let txs = rewards(4);

        let block = Block::new(&genesis, txs.clone(), DIFFICULTY);
        let other = Block::new(&genesis, rewards(6), DIFFICULTY);

        let proof = block.proof_for(&txs[1]).unwrap();

        assert!(block.header.verify_inclusion(&txs[1], &proof));
        assert!(!other.header.verify_inclusion(&txs[1], &proof));
    }

    #[test]
    fn an_empty_block_has_no_tree_and_proves_nothing() {
        let genesis = Block::genesis(DIFFICULTY);

        assert!(genesis.tree().is_none());
        assert_eq!(genesis.proof_for(&reward_to("alice", 50, 0)), None);
    }

    #[test]
    fn the_trees_root_is_the_root_the_header_sealed() {
        let (_, block) = mined(rewards(7));

        assert_eq!(block.tree().unwrap().root(), block.root());
    }
}
