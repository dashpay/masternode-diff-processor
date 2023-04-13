use crate::crypto::UInt384;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct OperatorPublicKey {
    pub data: UInt384,
    pub version: u16,
}

impl OperatorPublicKey {
    pub fn is_basic(&self) -> bool {
        self.version >= 2
    }
    pub fn is_legacy(&self) -> bool {
        self.version < 2
    }
}
