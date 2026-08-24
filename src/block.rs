use crate::transaction::Transaction;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Hash = [u8; 32];

pub const ZERO_HASH: Hash = [0u8; 32];

#[derive(Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub txs: Vec<Transaction>,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub pow: u64,
    pub hash: [u8; 32],
}

impl Block {
    pub fn new(prev: &Block, txs: Vec<Transaction>) -> Self {
        let mut block = Self {
            index: prev.index + 1,
            txs,
            timestamp: now(),
            prev_hash: prev.hash,
            pow: 0,
            hash: ZERO_HASH,
        };

        block.hash = block.compute_hash();
        block
    }

    pub fn genesis() -> Self {
        let mut block = Self {
            index: 0,
            txs: Vec::new(),
            timestamp: 0,
            prev_hash: ZERO_HASH,
            pow: 0,
            hash: ZERO_HASH,
        };

        block.hash = block.compute_hash();
        block
    }

    pub fn compute_hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(self.index.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.pow.to_be_bytes());

        for tx in &self.txs {
            hasher.update(tx.hash_bytes());
        }

        hasher.finalize().into()
    }

    pub fn mine(&mut self, difficulty: u32) {
        loop {
            self.hash = self.compute_hash();
            if meets_difficulty(&self.hash, difficulty) {
                break;
            }
            self.pow += 1;
        }
    }

    pub fn has_valid_hash(&self, difficulty: u32) -> bool {
        self.compute_hash() == self.hash && meets_difficulty(&self.hash, difficulty)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .expect("system clock is before the Unix epoch")
}

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
