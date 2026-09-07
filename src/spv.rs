use crate::{block::BlockHeader, error::ChainError, merkle::MerkleProof, transaction::Transaction};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A SPV client that holds block headers
/// for the sole purpose of verifying payments.
pub struct LightClient {
    headers: Vec<BlockHeader>,
}

impl LightClient {
    /// Verifies `headers` as a chain and keeps them, or reports the first one
    /// that breaks a structural rule.
    pub fn sync(headers: Vec<BlockHeader>, difficulty: u32) -> Result<Self, ChainError> {
        verify_headers(&headers, difficulty)?;

        Ok(Self { headers })
    }

    /// Returns the headers the client synchronised.
    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }
    /// Returns a reference to the block header at `height`, if any.
    pub fn header_at(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(usize::try_from(height).ok()?)
    }

    /// Returns `true` if `proof` shows that `tx` was recorded in the block at
    /// `height`.
    pub fn verify_tx(&self, tx: &Transaction, height: u64, proof: &MerkleProof) -> bool {
        self.header_at(height)
            .is_some_and(|head| head.verify_inclusion(tx, proof))
    }
}

/// Verifies POW of each header while skipping transaction checks.
///
///  # Errors
/// Returns a `ChainError` naming the first header that breaks a rule.
pub fn verify_headers(headers: &[BlockHeader], difficulty: u32) -> Result<(), ChainError> {
    for (pos, head) in headers.iter().enumerate() {
        // check block height
        if pos as u64 != head.height {
            return Err(ChainError::WrongHeight(head.height));
        }

        // check pow
        if !head.has_valid_pow(difficulty) {
            return Err(ChainError::BrokenHash(head.height));
        }
        // check hash link between two headers
        if pos > 0 && head.prev_hash != headers[pos - 1].hash() {
            return Err(ChainError::BrokenLink(head.height));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::blockchain::Blockchain;
    use crate::transaction::Transaction;
    use crate::wallet::Wallet;

    const DIFFICULTY: u32 = 8;

    fn chain() -> Blockchain {
        let mut chain = Blockchain::new(DIFFICULTY, 50);

        let alice = Wallet::from_seed("alice");
        let bob = Wallet::from_seed("bob");
        let carol = Wallet::from_seed("carol");

        chain.mine_pending(&alice.address());
        chain
            .queue_tx(Transaction::transfer(&alice, bob.address(), 10, 0))
            .unwrap();
        chain
            .queue_tx(Transaction::transfer(&alice, carol.address(), 5, 1))
            .unwrap();
        chain.mine_pending(&bob.address());

        chain
    }

    #[test]
    fn a_client_syncs_the_headers_of_a_valid_chain() {
        let chain = chain();
        let client = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();

        assert_eq!(client.headers().len(), chain.blocks().len());
    }

    #[test]
    fn headers_do_not_grow_with_the_transactions_beneath_them() {
        let chain = chain();

        // block 2 carries three transactions, block 1 carries one, and their
        // headers are the same size
        assert_eq!(chain.blocks()[2].txs().len(), 3);
        assert_eq!(chain.blocks()[1].txs().len(), 1);
        assert_eq!(
            size_of_val(&chain.headers()[1]),
            size_of_val(&chain.headers()[2])
        );
    }

    #[test]
    fn a_client_verifies_a_transaction_it_never_held() {
        let chain = chain();
        let client = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();

        let block = &chain.blocks()[2];
        let tx = &block.txs()[1];
        let proof = block.proof_for(tx).unwrap();

        assert!(client.verify_tx(tx, 2, &proof));
    }

    #[test]
    fn every_transaction_in_the_chain_proves_itself_to_the_client() {
        let chain = chain();
        let client = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();

        for block in chain.blocks() {
            for tx in block.txs() {
                let proof = block.proof_for(tx).unwrap();

                assert!(client.verify_tx(tx, block.height(), &proof));
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_at_the_wrong_height() {
        let chain = chain();
        let client = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();

        let block = &chain.blocks()[2];
        let tx = &block.txs()[0];
        let proof = block.proof_for(tx).unwrap();

        assert!(client.verify_tx(tx, 2, &proof));
        assert!(!client.verify_tx(tx, 1, &proof));
        assert!(!client.verify_tx(tx, 99, &proof));
    }

    #[test]
    fn a_transaction_that_was_never_mined_cannot_be_proved() {
        let chain = chain();
        let client = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();

        let block = &chain.blocks()[2];
        let real = &block.txs()[1];
        let proof = block.proof_for(real).unwrap();

        let mallory = Wallet::from_seed("mallory");
        let forged = Transaction::reward(mallory.address(), 9_999, 2);

        assert!(!client.verify_tx(&forged, 2, &proof));
    }

    #[test]
    fn a_client_rejects_headers_whose_work_was_not_done() {
        let chain = chain();
        let mut headers = chain.headers();

        headers[1].timestamp += 3_600;

        assert_eq!(
            LightClient::sync(headers, DIFFICULTY),
            Err(ChainError::BrokenHash(1))
        );
    }

    #[test]
    fn a_client_rejects_headers_that_do_not_link() {
        let chain = chain();
        let mut headers = chain.headers();

        // re-mine the tampered header so its own work is valid again; the
        // link to it, held by the header that follows, is what gives it away
        headers[1].timestamp += 3_600;
        while !headers[1].has_valid_pow(DIFFICULTY) {
            headers[1].pow += 1;
        }

        assert_eq!(
            LightClient::sync(headers, DIFFICULTY),
            Err(ChainError::BrokenLink(2))
        );
    }

    #[test]
    fn a_client_rejects_headers_out_of_order() {
        let chain = chain();
        let mut headers = chain.headers();

        headers.swap(1, 2);

        assert_eq!(
            LightClient::sync(headers, DIFFICULTY),
            Err(ChainError::WrongHeight(2))
        );
    }

    #[test]
    fn rewriting_the_tip_is_beyond_what_headers_alone_can_catch() {
        let chain = chain();
        let mut headers = chain.headers();
        let tip = headers.len() - 1;

        let mallory = Wallet::from_seed("mallory");
        let forged = Transaction::reward(mallory.address(), 9_999, tip as u64);

        // mallory rewrites the tip's root to cover her own transaction, then
        // redoes the work
        headers[tip].root = Block::tx_root(std::slice::from_ref(&forged));
        headers[tip].pow = 0;
        while !headers[tip].has_valid_pow(DIFFICULTY) {
            headers[tip].pow += 1;
        }

        // no later header links to the tip, so the structural rules have
        // nothing to contradict. Preferring the honest tip takes the longest
        // chain rule, which weighs accumulated work rather than checking one
        // header at a time, and this chain does not implement it yet
        assert!(LightClient::sync(headers, DIFFICULTY).is_ok());

        // a client on the honest headers is unmoved: the forged transaction
        // has no path to the root that header sealed
        let honest = LightClient::sync(chain.headers(), DIFFICULTY).unwrap();
        let block = chain.last_block();
        let proof = block.proof_for(&block.txs()[0]).unwrap();

        assert!(!honest.verify_tx(&forged, tip as u64, &proof));
    }
}
