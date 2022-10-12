#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OperatorPublicKey {
    // 84 // 692
    pub block_hash: [u8; 32],
    pub block_height: u32,
    pub key: [u8; 48],
}
