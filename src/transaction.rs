use crate::{
    error::{
        SignatureError,
        SignatureError::{Invalid, Missing},
        TxError,
    },
    wallet::Address,
};
use ed25519_dalek::Signature;
use std::fmt::{self};

// ensures that nothing signed elsewhere
// can ever be read as a transaction
pub(crate) const TX_DOMAIN: &[u8] = b"bloxshein.tx.v1";

// byte count of the largest Transaction payload
// prefix + tag + from + to + amount + nonce
const MAX_TX_PAYLOAD: usize = TX_DOMAIN.len() + 1 + 32 + 32 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Sheinbase,
    Account(Address),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    // prevents replay attacks
    pub nonce: u64,
    pub from: Sender,
    pub to: Address,
    pub amount: u64,
    // a reward tx is not signed
    pub signature: Option<Signature>,
}

impl Transaction {
    /// Builds an unsigned `Transaction`.
    pub fn new(from: Address, to: Address, amount: u64, nonce: u64) -> Self {
        Self {
            from: Sender::Account(from),
            to,
            amount,
            nonce,
            signature: None,
        }
    }

    pub fn sent_by(&self, address: &Address) -> bool {
        self.from == Sender::Account(*address)
    }

    /// Extracts the transaction's payload into an owned `Vec` of bytes.
    ///
    /// Use this method when signing a transaction.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_TX_PAYLOAD);

        bytes.extend_from_slice(TX_DOMAIN);

        // add a tag byte for sender variants to
        // differentiate fields when unpacking
        // format: sheinbase -> 0, others -> 1
        match self.from {
            Sender::Sheinbase => bytes.push(0),
            Sender::Account(addr) => {
                bytes.push(1);
                bytes.extend_from_slice(&addr.to_bytes())
            }
        }

        bytes.extend_from_slice(&self.to.to_bytes());
        bytes.extend_from_slice(&self.amount.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());

        bytes
    }

    /// Extracts the whole transaction into an owned `Vec` of bytes.
    ///
    /// Use this method when hashing a `Transaction`.
    pub fn hash_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes();

        // the signature is part of a transaction's identity,
        // so a tag byte marks which of the two shapes this is
        match &self.signature {
            Some(s) => {
                bytes.push(1);
                bytes.extend_from_slice(&s.to_bytes());
            }
            None => bytes.push(0),
        }

        bytes
    }

    pub(crate) fn reward(to: Address, amount: u64, height: u64) -> Self {
        Self {
            from: Sender::Sheinbase,
            to,
            amount,
            nonce: height,
            signature: None,
        }
    }

    pub fn is_reward(&self) -> bool {
        self.from == Sender::Sheinbase
    }

    /// Verifies whether the transaction was authorised by its sender.
    pub fn verify_sign(&self) -> Result<(), TxError> {
        match (self.from, &self.signature) {
            (Sender::Sheinbase, None) => Ok(()),
            (Sender::Sheinbase, Some(_)) => Err(TxError::Signature(
                SignatureError::SignedSheinbase(self.nonce),
            )),
            (Sender::Account(addr), Some(s)) => {
                if addr.verify(&self.signing_bytes(), s) {
                    Ok(())
                } else {
                    Err(TxError::Signature(Invalid(self.nonce)))
                }
            }
            (Sender::Account(_), None) => Err(TxError::Signature(Missing(self.nonce))),
        }
    }
}

impl fmt::Display for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sheinbase => write!(f, " Sheinbase"),
            Self::Account(addr) => write!(f, "{addr}"),
        }
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: {}", self.from, self.to, self.amount)
    }
}
