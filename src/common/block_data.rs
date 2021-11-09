use crate::crypto::byte_util::UInt256;

// #[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct BlockData {
    pub height: u32,
    pub hash: UInt256,
}
