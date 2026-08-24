use crate::{
    blockchain::Blockchain,
    transaction::Transaction,
    wallet::{Address, Wallet},
};

mod block;
mod blockchain;
mod error;
mod transaction;
mod wallet;

const DIFFICULTY: u32 = 6;
const MINING_REWARD: u64 = 50;

fn main() {
    let alice = Wallet::from_seed("alice");
    let bob = Wallet::from_seed("bob");
    let carol = Wallet::from_seed("carol");
    let dave = Wallet::from_seed("dave");
    let mallory = Wallet::from_seed("mallory");

    // addresses are public keys
    // here, we associate names to keep output readable
    let book = [
        ("alice", alice.address()),
        ("bob", bob.address()),
        ("carol", carol.address()),
        ("dave", dave.address()),
        ("mallory", mallory.address()),
    ];

    let mut chain = Blockchain::new(DIFFICULTY, MINING_REWARD);

    println!(
        "bloxshein — difficulty {}, reward {MINING_REWARD}\n",
        chain.difficulty()
    );

    println!("alice mines the first block");
    mine(&mut chain, &alice.address());

    println!("running some transactions...");

    submit(&mut chain, signed(&alice, bob.address(), 30, 0));
    submit(&mut chain, signed(&alice, carol.address(), 15, 1));
    submit(&mut chain, signed(&alice, dave.address(), 100, 2));

    println!(
        "\nbob mines {} pending transaction(s)",
        chain.pending().len()
    );
    mine(&mut chain, &bob.address());

    println!("\nbalances");
    for (name, addr) in book {
        println!(" {name:<8} {}", chain.balance_of(&addr));
    }

    println!("\nchain");
    for block in chain.blocks() {
        println!(
            "  #{} nonce {:<8} hash {}  ({} tx)",
            block.index,
            block.pow,
            &hex::encode(block.hash)[..16],
            block.txs.len()
        );
    }

    println!("\nvalid: {}", chain.is_valid());

    off_chain_signing(&chain, &alice, &mallory);
}

/// A wallet signs off-chain messages too, so it has to make sure it is never
/// tricked into signing a transaction while it believes it is signing
/// something harmless.
fn off_chain_signing(chain: &Blockchain, alice: &Wallet, mallory: &Wallet) {
    println!("\noff-chain signing");

    // an ordinary challenge: nothing about it can be read as a transaction
    let challenge = b"bloxshein.login: prove you hold alice's key";

    match alice.sign_challenge(challenge) {
        Ok(sign) => println!(
            "  login challenge signed, verifies: {}",
            alice.address().verify(challenge, &sign)
        ),
        Err(e) => println!("  login challenge refused ({e})"),
    }

    // mallory hands alice a "challenge" that is really the payload of a
    // transfer draining alice's balance into mallory's address
    let theft = Transaction::new(
        alice.address(),
        mallory.address(),
        chain.balance_of(&alice.address()),
        chain.next_nonce(&alice.address()),
    );

    // the domain prefix is what gives it away
    match alice.sign_challenge(&theft.signing_bytes()) {
        Ok(_) => println!("  disguised transfer signed: {theft}"),
        Err(e) => println!("  disguised transfer refused ({e}): {theft}"),
    }
}

/// Builds a transfer and signs it with the sender's key.
fn signed(from: &Wallet, to: Address, amount: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction::new(from.address(), to, amount, nonce);
    tx.signature = Some(from.sign_tx(&tx));
    tx
}

fn mine(chain: &mut Blockchain, miner: &Address) {
    let start = std::time::Instant::now();

    let block = chain.mine_pending(miner);

    println!(
        "  block #{} mined in {:?} after {} hashes -> {}",
        block.index,
        start.elapsed(),
        block.pow,
        hex::encode(block.hash)
    );
}

fn submit(chain: &mut Blockchain, tx: Transaction) {
    match chain.add_transaction(tx.clone()) {
        Ok(()) => println!(" queued {tx}"),
        Err(e) => println!(" rejected {tx} ({e})"),
    }
}
