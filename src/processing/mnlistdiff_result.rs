use std::collections::BTreeMap;
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
