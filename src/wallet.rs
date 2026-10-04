use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::{error::WalletError, transaction::TX_DOMAIN};

/// The public half of a wallet's key pair, identifying an account on the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 32]);

impl Address {
    /// Returns `true` if `signature` is this address's signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.key().verify_strict(message, signature).is_ok()
    }

    /// Returns the raw bytes of the underlying public key.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("an Address always holds a valid key")
    }
}

/// Shows an address as the hex of its first four bytes.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.to_bytes())[..8])
    }
}

/// Stores a private key and derived blockchain address.
pub struct Wallet {
    signing_key: SigningKey,
}

impl Wallet {
    /// Creates a wallet around a freshly generated random key.
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand_core::OsRng),
        }
    }

    /// Creates a wallet whose key is derived deterministically from `seed`.
    ///
    /// Reproducible by anyone holding the seed, so it suits demos and tests
    /// rather than keys that guard real balances.
    pub fn from_seed(seed: &str) -> Self {
        let digest: [u8; 32] = Sha256::digest(seed.as_bytes()).into();

        Self {
            signing_key: SigningKey::from_bytes(&digest),
        }
    }

    /// Returns the address derived from the wallet's public key.
    pub fn address(&self) -> Address {
        Address(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs an off-chain `challenge`, refusing any message that could later
    /// be replayed as a transaction.
    ///
    /// # Errors
    /// Returns `WalletError::ReservedDomain` if `challenge` opens with the
    /// transaction domain prefix.
    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<Signature, WalletError> {
        if challenge.starts_with(TX_DOMAIN) {
            return Err(WalletError::ReservedDomain);
        }

        Ok(self.sign(challenge))
    }

    /// Signs `message` with the wallet's private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::transaction::Transaction;

    #[test]
    fn a_seed_always_produces_the_same_address() {
        let seed1 = "meeowssss";
        let seed2 = "barkbark";

        let addr1 = Wallet::from_seed(seed1).address();
        let addr2 = Wallet::from_seed(seed1).address();

        assert_eq!(addr1, addr2);

        assert_ne!(
            Wallet::from_seed(seed1).address(),
            Wallet::from_seed(seed2).address()
        )
    }

    #[test]
    fn a_signature_only_verifies_under_the_signing_key() {
        let (alice, bob) = (Wallet::from_seed("meow"), Wallet::from_seed("bark"));

        // alice signs her message
        let msg = b"alice pays bob 10 meme coins";
        let sign = alice.sign(msg);

        // sign verified by alice's public key
        assert!(alice.address().verify(msg, &sign));
        // bob's public key cannot verify alice's sign
        assert!(!bob.address().verify(msg, &sign));

        // alice's sign cannot be used to verify other messages
        assert!(
            !alice
                .address()
                .verify(b"alice pays bob 10 mil meme coins", &sign)
        )
    }

    #[test]
    fn a_wallet_refuses_to_sign_a_transaction_as_a_challenge() {
        let (alice, mallory) = (Wallet::from_seed("meow"), Wallet::from_seed("bark"));

        // an ordinary challenge carries no transaction domain, so it is signed
        let challenge = b"prove you hold this key";
        let sign = alice.sign_challenge(challenge).unwrap();
        assert!(alice.address().verify(challenge, &sign));

        // mallory dresses a transfer out of alice's address up as a challenge.
        // signing it blindly would hand over a spendable signature
        let theft = Transaction::transfer_bytes(alice.address(), mallory.address(), 50, 0, 0);

        assert_eq!(
            alice.sign_challenge(&theft),
            Err(WalletError::ReservedDomain)
        );
    }
}
