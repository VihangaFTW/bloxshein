# bloxshein

A simple proof-of-work blockchain based on [Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf).

Currently under development. End goal is a blockchain simulator in a TUI maybe. The current codebase is inefficient and experimental.

If you are interested in understanding the code (very straightforward as of writing), you need to be familiar with:

- basic cybersecurity concepts such as digital signatures and cryptographic hash functions.
- a high level understanding of a [blockchain](https://www.youtube.com/watch?v=bBC-nXj3Ng4).

## Demo

Run demo:

```bash
cargo run --release
```

Below is a simplified explanation on what is happening in the demo.

The demo creates five wallets for alice, bob, carol, dave and mallory. An address is a
public key. The demo puts a name next to each one to keep the output easy
to read. Note that the print output shows the first four bytes of an address only.

1. **Alice mines block 1.** The blockchain always begins with a genesis block. So, Alice mines
   the next one. Mining means searching for a hash with enough leading zero
   bits. `DIFFICULTY` in `main.rs` sets how many zeros are required and each step up doubles the
   work. The miner is paid `MINING_REWARD` for successfully `mining` a block. In other words, this just means extending the blockchain with a new block. Alice now has 50 coins.
2. **Three transfers are queued.** Alice signs each one with her private key.
   She sends them to the mempool which is a store of pending transfers. The first sends 30 to bob. The second sends
   15 to carol. Both are accepted. Now, Alice has 5 left to spend but the third asks
   for 100 so it is rejected at once.
3. **Bob mines block 2.** The block picks up both pending transfers. Bob is
   paid a reward for creating a block so he is rewarded with 50. Now, bob has a total of 80 (30+50) coins.
4. **Check the blockchain's integrity** Then `is_valid()` replays
   every block from genesis, re-checking hashes, links, signatures, nonces
   and balances.
5. **Off-chain signing.** A wallet can also sign messages that are not
   transactions. A login challenge is one example. Mallory tries to abuse
   this by asking alice to sign a challenge. The challenge is really a malicious transfer that moves alice's balance to mallory. Every transaction payload
   starts with a reserved prefix and alice's wallet sees that prefix when it tries to sign and thus refuses to proceed any further.

## Tests

Run tests:

```bash
cargo test
```

## Current features

- Proof-of-work mining, with difficulty measured in leading zero bits
- SHA-256 hash-linked blocks, growing from a genesis block
- A mempool to hold pending transactions
- Mining rewards
- ed25519 wallets
- Signed transfers that reject replay attacks
- Transfer nonces so an accepted transfer cannot be resubmitted
- Full blockchain integrity check

## Planned Extensions

- difficulty retargeting
- Merkle trees
- transaction fees
- fork-choice rule
- networking or peers ?!
