use crate::ffi;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeList {
    pub block_hash: *mut [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: *mut [u8; 32], // nullable
    pub llmq_merkle_root: *mut [u8; 32], // nullable
    pub masternodes: *mut *mut ffi::types::MasternodeEntry,
    pub masternodes_count: usize,
    pub quorums: *mut *mut ffi::types::LLMQEntry,
    pub quorums_count: usize,
}
