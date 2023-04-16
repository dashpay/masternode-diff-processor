use crate::crypto::UInt256;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct Block {
    pub height: u32,
    pub hash: UInt256,
}

impl Block {
    pub fn new(height: u32, hash: UInt256) -> Self {
        Self { height, hash }
    }
}
