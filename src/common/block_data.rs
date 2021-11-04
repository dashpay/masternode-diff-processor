
#[repr(C)]
#[derive(Debug)]
pub struct BlockData {
    pub height: u32,
    pub hash: [u8; 32],
}
