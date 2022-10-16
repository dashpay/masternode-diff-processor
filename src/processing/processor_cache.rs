use dash_spv_models::common::LLMQType;
use dash_spv_models::llmq::{LLMQIndexedHash, LLMQSnapshot};
use dash_spv_models::masternode::{MasternodeEntry, MasternodeList};
use dash_spv_primitives::crypto::UInt256;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct MasternodeProcessorCache {
    pub llmq_members: BTreeMap<LLMQType, BTreeMap<UInt256, Vec<MasternodeEntry>>>,
    pub llmq_indexed_members: BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>,
    pub mn_lists: BTreeMap<UInt256, MasternodeList>,
    pub llmq_snapshots: BTreeMap<UInt256, LLMQSnapshot>,
    pub needed_masternode_lists: Vec<UInt256>,
}
impl Default for MasternodeProcessorCache {
    fn default() -> Self {
        MasternodeProcessorCache {
            llmq_members: BTreeMap::new(),
            llmq_indexed_members: BTreeMap::new(),
            llmq_snapshots: BTreeMap::new(),
            mn_lists: BTreeMap::new(),
            needed_masternode_lists: vec![],
        }
    }
}

impl std::fmt::Debug for MasternodeProcessorCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeProcessorCache")
            .field("llmq_members", &self.llmq_members)
            .field("llmq_indexed_members", &self.llmq_indexed_members)
            .field("llmq_snapshots", &self.llmq_snapshots)
            .field("mn_lists", &self.mn_lists)
            .field("needed_masternode_lists", &self.needed_masternode_lists)
            .finish()
    }
}

impl MasternodeProcessorCache {
    pub fn clear(&mut self) {
        self.llmq_members.clear();
        self.llmq_indexed_members.clear();
        self.mn_lists.clear();
        self.llmq_snapshots.clear();
        self.needed_masternode_lists.clear();
    }
    pub fn add_masternode_list(&mut self, block_hash: UInt256, list: MasternodeList) {
        self.mn_lists.insert(block_hash, list);
    }
    pub fn remove_masternode_list(&mut self, block_hash: UInt256) {
        self.mn_lists.remove(&block_hash);
    }
    pub fn add_snapshot(&mut self, block_hash: UInt256, snapshot: LLMQSnapshot) {
        self.llmq_snapshots.insert(block_hash, snapshot);
    }
    pub fn remove_snapshot(&mut self, block_hash: UInt256) {
        self.llmq_snapshots.remove(&block_hash);
    }
    pub fn get_quorum_members_of_type(
        &mut self,
        r#type: LLMQType,
    ) -> Option<&mut BTreeMap<UInt256, Vec<MasternodeEntry>>> {
        self.llmq_members.get_mut(&r#type)
    }

    pub fn get_indexed_quorum_members_of_type(
        &mut self,
        r#type: LLMQType,
    ) -> Option<&mut BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>> {
        self.llmq_indexed_members.get_mut(&r#type)
    }

    pub fn get_quorum_members(
        &mut self,
        r#type: LLMQType,
        block_hash: UInt256,
    ) -> Option<Vec<MasternodeEntry>> {
        let map_by_type_opt = self.get_quorum_members_of_type(r#type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&block_hash) {
                return Some(members.clone());
            }
        }
        None
    }
}
