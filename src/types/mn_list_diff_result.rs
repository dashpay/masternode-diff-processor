use crate::types;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MNListDiffResult {
    pub error_status: u8,
    pub base_block_hash: *mut [u8; 32],
    pub block_hash: *mut [u8; 32],
    pub has_found_coinbase: bool,       //1 byte
    pub has_valid_coinbase: bool,       //1 byte
    pub has_valid_mn_list_root: bool,   //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool,        //1 byte
    pub masternode_list: *mut types::MasternodeList,
    pub added_masternodes: *mut *mut types::MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes: *mut *mut types::MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_llmq_type_maps: *mut *mut types::LLMQMap,
    pub added_llmq_type_maps_count: usize,
    pub needed_masternode_lists: *mut *mut [u8; 32],
    pub needed_masternode_lists_count: usize,
}
impl MNListDiffResult {
    pub fn default_with_error(error: u8) -> Self {
        let mut result = Self::default();
        result.error_status = error;
        result
    }
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        MNListDiffResult {
            error_status: 0,
            base_block_hash: null_mut(),
            block_hash: null_mut(),
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes: null_mut(),
            modified_masternodes_count: 0,
            added_llmq_type_maps: null_mut(),
            added_llmq_type_maps_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0,
        }
    }
}

impl MNListDiffResult {
    pub fn is_valid(&self) -> bool {
        self.has_found_coinbase
            && self.has_valid_quorums
            && self.has_valid_mn_list_root
            && self.has_valid_llmq_list_root
    }
}
