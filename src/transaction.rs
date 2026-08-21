use std::fmt;

const SHEINBASE: &str = "SHEINBASE";

#[derive(Debug, Clone)]
pub struct Transaction {
    pub from: String,
    pub to: String,
    pub amount: u64,
}

impl Transaction {
    pub fn new(from: impl Into<String>, to: impl Into<String>, amount: u64) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            amount,
        }
    }

    pub fn reward(to: impl Into<String>, amount: u64) -> Self {
        Self::new(SHEINBASE, to, amount)
    }

    pub fn is_reward(&self) -> bool {
        self.from == SHEINBASE
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: {}", self.from, self.to, self.amount)
    }
}
