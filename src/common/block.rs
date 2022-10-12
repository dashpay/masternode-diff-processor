use dash_spv_primitives::crypto::UInt256;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct Block {
    pub height: u32,
    pub hash: UInt256,
}
