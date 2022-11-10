use crate::crypto::UInt384;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct OperatorPublicKey {
    pub data: UInt384,
    pub version: u16,
}
