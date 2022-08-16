use std::collections::BTreeMap;
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use dash_spv_ffi::types;
use dash_spv_models::common::LLMQType;
use dash_spv_models::masternode::{LLMQEntry, MasternodeEntry, MasternodeList};
use dash_spv_primitives::crypto::UInt256;

#[derive(Debug)]
pub struct MNListDiffResult {
    pub block_hash: UInt256,
    pub has_found_coinbase: bool, //1 byte
    pub has_valid_coinbase: bool, //1 byte
    pub has_valid_mn_list_root: bool, //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool, //1 byte
    pub masternode_list: MasternodeList,
    pub added_masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub modified_masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub added_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
    pub needed_masternode_lists:  Vec<UInt256>,
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        Self {
            block_hash: UInt256::MAX,
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: Default::default(),
            added_masternodes: Default::default(),
            modified_masternodes: Default::default(),
            added_quorums: Default::default(),
            needed_masternode_lists: vec![]
        }
    }
}

impl MNListDiffResult {
    pub fn encode(&self) -> types::MNListDiffResult {
        types::MNListDiffResult {
            block_hash: boxed(self.block_hash.0),
            has_found_coinbase: self.has_found_coinbase,
            has_valid_coinbase: self.has_valid_coinbase,
            has_valid_mn_list_root: self.has_valid_mn_list_root,
            has_valid_llmq_list_root: self.has_valid_llmq_list_root,
            has_valid_quorums: self.has_valid_quorums,
            masternode_list: boxed(self.masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&self.added_masternodes),
            added_masternodes_count: self.added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&self.modified_masternodes),
            modified_masternodes_count: self.modified_masternodes.len(),
            added_llmq_type_maps: encode_quorums_map(&self.added_quorums),
            added_llmq_type_maps_count: self.added_quorums.len(),
            needed_masternode_lists: boxed_vec(self.needed_masternode_lists.iter().map(|h|boxed(h.0)).collect()),
            needed_masternode_lists_count: self.needed_masternode_lists.len()
        }
    }
}
