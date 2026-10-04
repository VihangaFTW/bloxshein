use std::fmt;

use crate::{
    error::{
        SignatureError,
        TxError::{self},
    },
    wallet::{Address, Wallet},
};
use ed25519_dalek::Signature;

// ensures that nothing signed elsewhere
// can ever be read as a transaction
pub(crate) const TX_DOMAIN: &[u8] = b"bloxshein.tx.v2";

// 1 coin =  10^8 units
// used to represent fractional amounts in the chain
pub(crate) const UNIT: u64 = 100_000_000;

// byte count of the largest Transaction payload
// prefix + tag + from + to + amount + nonce + fee
const MAX_TX_PAYLOAD: usize = TX_DOMAIN.len() + 1 + 32 + 32 + 8 + 8 + 8;

/// A ledger entry: either coin minted by the chain for a miner, or a signed
/// transfer between two addresses.
#[derive(Debug, Clone, PartialEq)]
pub enum Transaction {
    /// Coin paid to the miner of the block at `height`.
    Reward {
        to: Address,
        amount: u64,
        height: u64,
    },
    /// A payment authorised by the sender's signature over its payload.
    Transfer {
        from: Address,
        to: Address,
        amount: u64,
        nonce: u64,
        // sender determines the fee. Miner prioritizes mining txs with higher fees.
        fee: u64,
        signature: Signature,
    },
}

impl Transaction {
    /// Builds a transfer of `amount` from `wallet` to `to`, signed with the
    /// wallet's key.
    pub fn transfer(wallet: &Wallet, to: Address, amount: u64, fee: u64, nonce: u64) -> Self {
        let from = wallet.address();

        Self::Transfer {
            from,
            to,
            amount,
            nonce,
            fee,
            signature: wallet.sign(Self::transfer_bytes(from, to, amount, fee, nonce).as_slice()),
        }
    }

    pub(crate) fn reward(to: Address, amount: u64, height: u64) -> Self {
        Self::Reward { to, amount, height }
    }

    pub(crate) fn fee(&self) -> u64 {
        match self {
            Self::Reward { .. } => 0,
            Self::Transfer { fee, .. } => *fee,
        }
    }

    /// Returns `true` if this is a transfer sent by `address`.
    pub fn sent_by(&self, address: &Address) -> bool {
        match self {
            Transaction::Transfer { from, .. } => from == address,
            _ => false,
        }
    }

    /// Returns `true` if this is a mining reward.
    pub fn is_reward(&self) -> bool {
        matches!(self, Self::Reward { .. })
    }

    /// The sender of a transfer, or `None` for a reward minted by the chain.
    pub fn sender(&self) -> Option<Address> {
        match self {
            Self::Reward { .. } => None,
            Self::Transfer { from, .. } => Some(*from),
        }
    }

    /// Returns the recipient of the transaction.
    pub fn to(&self) -> Address {
        match self {
            Self::Reward { to, .. } | Self::Transfer { to, .. } => *to,
        }
    }

    /// Returns the amount transferred, or the size of the reward.
    pub fn amount(&self) -> u64 {
        match self {
            Self::Reward { amount, .. } | Self::Transfer { amount, .. } => *amount,
        }
    }

    /// Returns the sender's nonce, or the block height for a reward.
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Reward { height, .. } => *height,
            Self::Transfer { nonce, .. } => *nonce,
        }
    }

    /// Verifies that a transfer was authorised by its sender. A reward carries
    /// no signature and is always accepted.
    ///
    /// # Errors
    /// Returns `TxError::SelfTransfer` if sender and recipient are the same
    /// address, or `TxError::Signature` if the signature does not verify under
    /// the sender's address.
    pub fn verify_transfer(&self) -> Result<(), TxError> {
        if let Self::Transfer {
            from,
            to,
            amount,
            nonce,
            fee,
            signature,
        } = self
        {
            if from == to {
                return Err(TxError::SelfTransfer);
            }

            let message = Self::transfer_bytes(*from, *to, *amount, *fee, *nonce);

            if !from.verify(&message, signature) {
                return Err(TxError::Signature(SignatureError::Invalid(*nonce)));
            }
        }
        Ok(())
    }

    pub(crate) fn transfer_bytes(
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_TX_PAYLOAD);

        bytes.extend_from_slice(TX_DOMAIN);
        bytes.push(1);
        bytes.extend_from_slice(&from.to_bytes());
        bytes.extend_from_slice(&to.to_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&nonce.to_be_bytes());
        bytes.extend_from_slice(&fee.to_be_bytes());

        bytes
    }

    fn reward_bytes(to: Address, amount: u64, nonce: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_TX_PAYLOAD);

        bytes.extend_from_slice(TX_DOMAIN);
        bytes.push(0);
        bytes.extend_from_slice(&to.to_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&nonce.to_be_bytes());

        bytes
    }

    /// Returns the transaction's canonical payload.
    pub(crate) fn payload_bytes(&self) -> Vec<u8> {
        match self {
            Self::Transfer {
                from,
                to,
                amount,
                nonce,
                fee,
                ..
            } => Self::transfer_bytes(*from, *to, *amount, *fee, *nonce),
            Self::Reward { to, amount, height } => Self::reward_bytes(*to, *amount, *height),
        }
    }

    /// Returns the transaction's canonical payload
    /// followed by the signature, if any.
    pub(crate) fn hash_bytes(&self) -> Vec<u8> {
        let mut bytes = self.payload_bytes();

        match self {
            Self::Transfer { signature, .. } => {
                bytes.push(1);
                bytes.extend_from_slice(&signature.to_bytes());
            }
            Self::Reward { .. } => bytes.push(0),
        }

        bytes
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reward { to, amount, .. } => write!(f, "Sheinbase -> {to}: {amount}"),
            Self::Transfer {
                from, to, amount, ..
            } => write!(f, "{from} -> {to}: {amount}"),
        }
    }
}
