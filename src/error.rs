use std::fmt;

// ============= WALLET =============

/// Reasons a `Wallet` refuses to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    ReservedDomain,
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedDomain => write!(f, "unsafe preimage"),
        }
    }
}

// ============= TRANSACTION =============

/// Reasons a signature fails to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    Invalid(u64),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(id) => write!(f, "invalid signature in transaction {id}"),
        }
    }
}

/// Reasons a `Transaction` is rejected, whether at admission to the mempool or
/// during chain validation.
#[derive(Debug, PartialEq, Clone)]
pub enum TxError {
    ZeroAmount,
    SelfTransfer,
    LowFee { min: u64, got: u64 },
    AmountOverflow,
    InsufficientFunds { available: u64, requested: u64 },
    WrongNonce { expected: u64, got: u64 },
    WrongReward { expected: u64, got: u64 },
    UnexpectedReward,
    Signature(SignatureError),
    MintingNotAllowed,
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxError::InsufficientFunds {
                available,
                requested,
            } => write!(f, "insufficient funds: have {available}, need {requested}"),
            TxError::SelfTransfer => write!(f, "sender and recipient must differ"),
            TxError::ZeroAmount => write!(f, "amount must be greater than zero"),
            TxError::LowFee { min, got } => {
                write!(f, "fee too low: minimum {min}, got {got}")
            }
            TxError::AmountOverflow => write!(f, "amount plus fee overflows"),
            TxError::WrongNonce { expected, got } => {
                write!(
                    f,
                    "unexpected nonce in transaction: expected {expected}, got {got}"
                )
            }
            TxError::UnexpectedReward => {
                write!(f, " a reward must be the first transaction in a block")
            }
            TxError::Signature(err) => write!(f, "cannot verify signature: {err}"),
            TxError::MintingNotAllowed => write!(f, "only mining may create coin"),
            Self::WrongReward { expected, got } => {
                write!(f, "invalid mining reward: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for TxError {}

impl From<SignatureError> for TxError {
    fn from(value: SignatureError) -> Self {
        Self::Signature(value)
    }
}

// ============= BLOCKCHAIN =============

/// Reasons a `Blockchain` fails validation.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainError {
    // structural errors in the blockchain
    WrongHeight(u64),
    BrokenHash(u64),
    BrokenRoot(u64),
    BrokenLink(u64),
    MissingReward(u64),
    // a transaction breaking a rule that would also reject it at admission
    BadTransaction {
        height: u64,
        slot: usize,
        cause: TxError,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::BrokenLink(h) => {
                write!(f, "previous hash of {h} does not match its parent")
            }
            ChainError::BrokenHash(h) => {
                write!(f, "block {h} hash does not match mining difficulty")
            }
            ChainError::BrokenRoot(h) => write!(
                f,
                "merkle root of block {h} does not cover its transactions"
            ),
            ChainError::WrongHeight(h) => write!(f, "invalid height for block {h}"),
            ChainError::MissingReward(h) => write!(f, "missing reward transaction in block {h}"),
            ChainError::BadTransaction {
                height,
                slot,
                cause,
            } => write!(f, "(block {height}, slot {slot}): {cause}"),
        }
    }
}
