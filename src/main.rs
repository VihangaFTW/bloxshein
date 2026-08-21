use crate::{blockchain::Blockchain, transaction::Transaction};

mod block;
mod blockchain;
mod error;
mod transaction;

const DIFFICULTY: u32 = 16;
const MINING_REWARD: u64 = 50;

fn main() {
    let mut chain = Blockchain::new(DIFFICULTY, MINING_REWARD);

    println!(
        "bloxshein — difficulty {}, reward {MINING_REWARD}\n",
        chain.difficulty()
    );

    println!("alice mines the first block");
    mine(&mut chain, "alice");

    println!("running some transactions...");

    submit(&mut chain, Transaction::new("alice", "bob", 30));
    submit(&mut chain, Transaction::new("alice", "carol", 15));
    submit(&mut chain, Transaction::new("alice", "dave", 100));

    println!(
        "\nbob mines {} pending transaction(s)",
        chain.pending().len()
    );
    mine(&mut chain, "bob");

    println!("\nbalances");
    for addr in ["alice", "bob", "carol", "dave"] {
        println!(" {addr:<6} {}", chain.balance_of(addr));
    }

    println!("\nchain");
    for block in chain.blocks() {
        println!(
            "  #{} nonce {:<8} hash {}  ({} tx)",
            block.index,
            block.nonce,
            &hex::encode(block.hash)[..16],
            block.txs.len()
        );
    }

    println!("\nvalid: {}", chain.is_valid());
}

fn mine(chain: &mut Blockchain, miner: &str) {
    let start = std::time::Instant::now();

    let block = chain.mine_pending(miner);

    println!(
        "  block #{} mined in {:?} after {} hashes -> {}",
        block.index,
        start.elapsed(),
        block.nonce,
        hex::encode(block.hash)
    );
}

fn submit(chain: &mut Blockchain, tx: Transaction) {
    match chain.add_transaction(tx.clone()) {
        Ok(()) => println!(" queued {tx}"),
        Err(e) => println!(" rejected {tx} ({e})"),
    }
}
