use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::{
    error::WalletError,
    transaction::{TX_DOMAIN, Transaction},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(VerifyingKey);

impl Address {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        VerifyingKey::from_bytes(bytes).map(Self)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.0.verify_strict(message, signature).is_ok()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Shows the first four bytes of a wallet address.
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
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand_core::OsRng),
        }
    }

    pub fn from_seed(seed: &str) -> Self {
        let digest: [u8; 32] = Sha256::digest(seed.as_bytes()).into();

        Self {
            signing_key: SigningKey::from_bytes(&digest),
        }
    }

    pub fn address(&self) -> Address {
        Address(self.signing_key.verifying_key())
    }

    pub fn sign_tx(&self, tx: &Transaction) -> Signature {
        self.sign_bytes(&tx.signing_bytes())
    }

    pub fn sign_challenge(&self, challenge: &[u8]) -> Result<Signature, WalletError> {
        if challenge.starts_with(TX_DOMAIN) {
            return Err(WalletError::ReservedDomain);
        }

        Ok(self.sign_bytes(challenge))
    }

    fn sign_bytes(&self, message: &[u8]) -> Signature {
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

    #[test]
    fn addresses_survive_a_round_trip_through_bytes() {
        // create wallet and extract public key/address
        let addr = Wallet::from_seed("meow").address();
        assert_eq!(Address::from_bytes(&addr.to_bytes()).unwrap(), addr);
    }

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
        let sign = alice.sign_bytes(msg);

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
        let theft = Transaction::new(alice.address(), mallory.address(), 50, 0);

        assert_eq!(
            alice.sign_challenge(&theft.signing_bytes()),
            Err(WalletError::ReservedDomain)
        );
    }
}
