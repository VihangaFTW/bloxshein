# bloxshein

A small proof-of-work blockchain based on [Bitcoin: A Peer-to-Peer Electronic Cash System](https://bitcoin.org/bitcoin.pdf).

## Demo

Run demo:

```bash
cargo run --release
```

The demo mines a block, queues three transfers (one of which is rejected for
insufficient funds), mines them into a second block, then prints balances and
validates the chain.

## Tests 

Run tests:

```bash
cargo test
```

## Planned Extensions

- [ ] digital signatures
- [ ] difficulty retargeting
- [ ] Merkle trees
- [ ] transaction fees
- [ ] fork-choice rule
- [ ] networking or peers ?!
