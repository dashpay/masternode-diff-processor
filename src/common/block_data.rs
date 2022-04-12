use dash_spv_primitives::crypto::byte_util::UInt256;

// #[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct BlockData {
    pub height: u32,
    pub hash: UInt256,
}
