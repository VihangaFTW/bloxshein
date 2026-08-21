use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ChainError {
    EmptyAddress,
    ZeroAmount,
    SelfTransfer,
    InsufficientFunds { available: u64, requested: u64 },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::EmptyAddress => write!(f, "address must not be empty"),
            ChainError::InsufficientFunds {
                available,
                requested,
            } => write!(f, "insufficient funds: have {available}, need {requested}"),
            ChainError::SelfTransfer => write!(f, "sender and recipient must differ"),
            ChainError::ZeroAmount => write!(f, "amount must be greater than zero"),
        }
    }
}

impl std::error::Error for ChainError {}

