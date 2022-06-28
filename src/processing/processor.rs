use std::cmp::min;
use std::collections::{BTreeMap, HashSet};
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetLLMQSnapshotByBlockHeight, MasternodeListDestroy, MasternodeListLookup, ShouldProcessLLMQTypeCallback, ValidateLLMQCallback};
use dash_spv_ffi::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use dash_spv_ffi::types;
use dash_spv_ffi::ffi::callbacks;
use dash_spv_models::common::{LLMQSnapshotSkipMode, LLMQType};
use dash_spv_models::{common, llmq, masternode};
use dash_spv_primitives::consensus::{Encodable, encode};
use dash_spv_primitives::crypto::byte_util::{Reversable, Zeroable};
use dash_spv_primitives::crypto::data_ops::{Data, inplace_intersection};
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::{Hash, sha256d};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum QuorumSelectionType {
    MN = 0,
    LLMQ = 1,
    LlmqRotation = 2
}


#[derive(Copy, Clone, Debug)]
pub struct ProcessorContext {
    pub selection_type: QuorumSelectionType,
    pub use_insight_as_backup: bool,
    pub base_masternode_list_hash: Option<UInt256>,
    pub merkle_root: UInt256,
}


#[derive(Clone, Debug)]
#[repr(C)]
pub struct MasternodeProcessorCache {
    pub map_quorum_members: BTreeMap<LLMQType, BTreeMap<UInt256, Vec<masternode::MasternodeEntry>>>,
    pub map_indexed_quorum_members: BTreeMap<LLMQType, BTreeMap<llmq::LLMQIndexedHash, Vec<masternode::MasternodeEntry>>>,
}
impl Default for MasternodeProcessorCache {
    fn default() -> Self {
        MasternodeProcessorCache {
            map_quorum_members: BTreeMap::new(),
            map_indexed_quorum_members: BTreeMap::new(),
        }
    }
}

#[repr(C)]
pub struct MasternodeProcessor {
    /// External Masternode Manager Diff Message Context
    pub context: *const std::ffi::c_void,
    pub get_block_height_by_hash: GetBlockHeightByHash,
    get_block_hash_by_height: GetBlockHashByHeight,
    get_llmq_snapshot_by_block_height: GetLLMQSnapshotByBlockHeight,
    get_masternode_list_by_block_hash: MasternodeListLookup,
    destroy_masternode_list: MasternodeListDestroy,
    add_insight: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq: ValidateLLMQCallback,
}
impl std::fmt::Debug for MasternodeProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeProcessor")
            .field("context", &self.context)
            .finish()
    }
}

impl MasternodeProcessor {
    pub fn new(
        get_block_height_by_hash: GetBlockHeightByHash,
        get_block_hash_by_height: GetBlockHashByHeight,
        get_llmq_snapshot_by_block_height: GetLLMQSnapshotByBlockHeight,
        get_masternode_list_by_block_hash: MasternodeListLookup,
        destroy_masternode_list: MasternodeListDestroy,
        add_insight: AddInsightBlockingLookup,
        should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
        validate_llmq: ValidateLLMQCallback,
        context: *const std::ffi::c_void) -> Self {
        Self {
            get_block_height_by_hash,
            get_block_hash_by_height,
            get_llmq_snapshot_by_block_height,
            get_masternode_list_by_block_hash,
            destroy_masternode_list,
            add_insight,
            should_process_llmq_of_type,
            validate_llmq,
            context,
        }
    }

    pub(crate) fn get_list_diff_result(&self, list_diff: llmq::MNListDiff, processor_context: ProcessorContext, cache: &mut MasternodeProcessorCache) -> types::MNListDiffResult {
        let block_hash = list_diff.block_hash;
        let (base_masternodes, base_quorums) = self.lookup_masternodes_and_quorums_for(processor_context.base_masternode_list_hash);
        let block_height = list_diff.block_height;
        let coinbase_transaction = list_diff.coinbase_transaction;
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (added_masternodes,
            modified_masternodes,
            masternodes) = self.classify_masternodes(
            base_masternodes,
            list_diff.added_or_modified_masternodes,
            list_diff.deleted_masternode_hashes,
            block_height,
            block_hash
        );
        //println!("MNListDiffResult.from_diff.base_quorums: \n[{:?}] \nadded_quorums:\n [{:?}]", base_quorums.clone(), list_diff.added_quorums.clone());
        let (added_quorums,
            quorums,
            has_valid_quorums,
            needed_masternode_lists) = self.classify_quorums(
            base_quorums,
            list_diff.added_quorums,
            list_diff.deleted_quorums,
            processor_context,
            cache
        );
        //println!("MNListDiffResult.from_diff.added_quorums: \n[{:?}] \nquorums:\n [{:?}]", added_quorums.clone(), quorums.clone());
        let masternode_list = masternode::MasternodeList::new(masternodes, quorums, block_hash, block_height, quorums_active);
        let has_valid_mn_list_root = masternode_list.has_valid_mn_list_root(&coinbase_transaction);
        let tree_element_count = list_diff.total_transactions;
        let hashes = list_diff.merkle_hashes;
        let flags = list_diff.merkle_flags;
        let has_found_coinbase = coinbase_transaction.has_found_coinbase(hashes);
        let merkle_tree = common::MerkleTree { tree_element_count, hashes, flags };
        let has_valid_quorum_list_root = !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction);
        let needed_masternode_lists_count = needed_masternode_lists.len();
        types::MNListDiffResult {
            block_hash: boxed(list_diff.block_hash.clone().0),
            has_found_coinbase,
            has_valid_coinbase: merkle_tree.has_root(processor_context.merkle_root),
            has_valid_mn_list_root,
            has_valid_llmq_list_root: has_valid_quorum_list_root,
            has_valid_quorums,
            masternode_list: boxed(masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&added_masternodes),
            added_masternodes_count: added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&modified_masternodes),
            modified_masternodes_count: modified_masternodes.len(),
            added_llmq_type_maps: encode_quorums_map(&added_quorums),
            added_llmq_type_maps_count: added_quorums.len(),
            needed_masternode_lists: boxed_vec(needed_masternode_lists),
            needed_masternode_lists_count
        }
    }

    pub fn classify_masternodes(&self,
                                base_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
                                added_or_modified_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
                                deleted_masternode_hashes: Vec<UInt256>,
                                block_height: u32,
                                block_hash: UInt256)
                                -> (BTreeMap<UInt256, masternode::MasternodeEntry>,
                                    BTreeMap<UInt256, masternode::MasternodeEntry>,
                                    BTreeMap<UInt256, masternode::MasternodeEntry>) {
        let added_or_modified_masternodes = added_or_modified_masternodes;
        let deleted_masternode_hashes = deleted_masternode_hashes;
        let mut added_masternodes = added_or_modified_masternodes.clone();
        let mut modified_masternode_keys: HashSet<UInt256> = HashSet::new();
        if base_masternodes.len() > 0 {
            let base_masternodes = base_masternodes.clone();
            base_masternodes
                .iter()
                .for_each(|(h, _e)| { added_masternodes.remove(h); });
            let mut new_mn_keys: HashSet<UInt256> = added_or_modified_masternodes
                .keys()
                .cloned()
                .collect();
            let mut old_mn_keys: HashSet<UInt256> = base_masternodes
                .keys()
                .cloned()
                .collect();
            modified_masternode_keys = inplace_intersection(&mut new_mn_keys, &mut old_mn_keys);
        }
        let mut modified_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry> = modified_masternode_keys
            .clone()
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, hash| {
                acc.insert(hash, added_or_modified_masternodes[&hash].clone());
                acc
            });
        let mut masternodes = if base_masternodes.len() > 0 {
            let mut old_mnodes = base_masternodes.clone();
            for hash in deleted_masternode_hashes {
                old_mnodes.remove(&hash.clone().reversed());
            }
            old_mnodes.extend(added_masternodes.clone());
            old_mnodes
        } else {
            added_masternodes.clone()
        };
        modified_masternodes.iter_mut().for_each(|(hash, modified)| {
            if let Some(mut old) = masternodes.get_mut(hash) {
                if (*old).update_height < (*modified).update_height {
                    if (*modified).provider_registration_transaction_hash == (*old).provider_registration_transaction_hash {
                        (*modified).update_with_previous_entry(old, common::Block { height: block_height, hash: block_hash });
                    }
                    if !(*old).confirmed_hash.is_zero() &&
                        (*old).known_confirmed_at_height.is_some() &&
                        (*old).known_confirmed_at_height.unwrap() > block_height {
                        (*old).known_confirmed_at_height = Some(block_height);
                    }
                }
                masternodes.insert((*hash).clone(), (*modified).clone());
            }
        });
        (added_masternodes, modified_masternodes, masternodes)
    }

    pub fn classify_quorums(&self,
                            base_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
                            added_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
                            deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>>,
                            processor_context: ProcessorContext,
                            cache: &mut MasternodeProcessorCache,
    )
                            -> (BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
            BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
            bool,
            Vec<*mut [u8; 32]>
        ) {
        let has_valid_quorums = true;
        let mut needed_masternode_lists: Vec<*mut [u8; 32]> = Vec::new();
        added_quorums
            .iter()
            .for_each(|(&llmq_type, llmqs_of_type)| {
                if self.should_process_quorum(llmq_type) {
                    (*llmqs_of_type).iter().for_each(|(&llmq_block_hash, quorum)| {
                        match self.lookup_masternode_list(llmq_block_hash) {
                            Some(llmq_masternode_list) =>
                                self.validate_quorum(
                                    quorum.clone(),
                                    has_valid_quorums,
                                    llmq_masternode_list,
                                    processor_context,
                                    cache
                                ),
                            None =>
                                if self.lookup_block_height_by_hash(llmq_block_hash) != u32::MAX {
                                    needed_masternode_lists.push(boxed(llmq_block_hash.0));
                                } else if processor_context.use_insight_as_backup {
                                    self.add_insight(llmq_block_hash);
                                    if self.lookup_block_height_by_hash(llmq_block_hash) != u32::MAX {
                                        needed_masternode_lists.push(boxed(llmq_block_hash.0));
                                    }
                                }
                        }
                    });
                }
            });
        let mut quorums = base_quorums.clone();
        quorums.extend(added_quorums
            .clone()
            .into_iter()
            .filter(|(key, _entries)| !quorums.contains_key(key))
            .collect::<BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>>());
        quorums.iter_mut().for_each(|(llmq_type, llmq_map)| {
            if let Some(keys_to_delete) = deleted_quorums.get(llmq_type) {
                keys_to_delete.into_iter().for_each(|key| {
                    (*llmq_map).remove(key);
                });
            }
            if let Some(keys_to_add) = added_quorums.get(llmq_type) {
                keys_to_add.clone().into_iter().for_each(|(key, entry)| {
                    (*llmq_map).insert(key, entry);
                });
            }
        });
        (added_quorums, quorums, has_valid_quorums, needed_masternode_lists)
    }

    pub fn validate_quorum(
        &self,
        quorum: masternode::LLMQEntry,
        has_valid_quorums: bool,
        llmq_masternode_list: masternode::MasternodeList,
        processor_context: ProcessorContext,
        cache: &mut MasternodeProcessorCache,
    ) {
        let block_hash = llmq_masternode_list.block_hash;
        let block_height = self.lookup_block_height_by_hash(block_hash);
        let quorum_modifier = quorum.llmq_quorum_hash();
        let quorum_count = quorum.llmq_type.size();
        let valid_masternodes = if processor_context.selection_type == QuorumSelectionType::LlmqRotation {
            self.get_rotated_masternodes_for_quorum(
                quorum.llmq_type,
                block_hash,
                block_height,
                cache
            )
        } else {
            Self::valid_masternodes_for(llmq_masternode_list.masternodes, quorum_modifier, quorum_count, block_height)
        };
        self.validate_signature(valid_masternodes, quorum, block_height, has_valid_quorums);
    }

    pub fn score_masternodes(masternodes: Vec<masternode::MasternodeEntry>, quorum_modifier: UInt256, block_height: u32) -> BTreeMap<UInt256, masternode::MasternodeEntry> {
        masternodes
            .into_iter()
            .fold(BTreeMap::new(),|mut map, entry| {
                match masternode::MasternodeList::masternode_score(entry.clone(), quorum_modifier, block_height) {
                    Some(score) => {
                        if !score.0.is_empty() {
                            map.insert(score, entry);
                        }
                    },
                    None => {}
                };
                map
            })
    }
    pub fn score_masternodes_map(masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>, quorum_modifier: UInt256, block_height: u32) -> BTreeMap<UInt256, masternode::MasternodeEntry> {
        masternodes.clone().into_iter().filter_map(|(_, entry)| {
            let score = masternode::MasternodeList::masternode_score(entry.clone(), quorum_modifier, block_height);
            if score.is_some() && !score.unwrap().0.is_empty() {
                Some((score.unwrap(), entry))
            } else {
                None
            }
        }).collect()
    }


    pub fn get_valid_masternodes(mut scored_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>, quorum_count: u32, masternodes_in_list_count: usize, block_height: u32) -> Vec<masternode::MasternodeEntry> {
        let mut scores: Vec<UInt256> = scored_masternodes.clone().into_keys().collect();
        scores.sort_by(|&s1, &s2| s2.clone().reversed().cmp(&s1.clone().reversed()));
        let mut valid_masternodes: Vec<masternode::MasternodeEntry> = Vec::new();
        let count = min(masternodes_in_list_count, scores.len());
        for i in 0..count {
            if let Some(masternode) = scored_masternodes.get_mut(&scores[i]) {
                if (*masternode).is_valid_at(block_height) {
                    valid_masternodes.push((*masternode).clone());
                }
            }
            if valid_masternodes.len() == quorum_count as usize {
                break;
            }
        }
        valid_masternodes
    }

    pub fn valid_masternodes_for_quorum(masternodes: Vec<masternode::MasternodeEntry>, quorum_modifier: UInt256, quorum_count: u32, block_height: u32) -> Vec<masternode::MasternodeEntry> {
        let masternodes_in_list_count = masternodes.len();
        let score_dictionary = Self::score_masternodes(masternodes, quorum_modifier, block_height);
        Self::get_valid_masternodes(score_dictionary, quorum_count, masternodes_in_list_count, block_height)
    }

    pub fn valid_masternodes_for(masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>, quorum_modifier: UInt256, quorum_count: u32, block_height: u32) -> Vec<masternode::MasternodeEntry> {
        let masternodes_in_list_count = masternodes.len();
        let score_dictionary = Self::score_masternodes_map(masternodes, quorum_modifier, block_height);
        Self::get_valid_masternodes(score_dictionary, quorum_count, masternodes_in_list_count, block_height)
    }

    // Same as in LLMQEntry
// TODO: migrate to LLMQEntry
    fn build_llmq_modifier(llmq_type: LLMQType, block_hash: UInt256) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(33);
        let offset: &mut usize = &mut 0;
        *offset += encode::VarInt(llmq_type as u64).consensus_encode(&mut buffer).unwrap();
        *offset += block_hash.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    // Quorum members dichotomy in snapshot
    fn masternode_usage_by_snapshot(
        &self,
        llmq_type: LLMQType,
        block_height: u32,
        snapshot: llmq::LLMQSnapshot)
        -> (Vec<masternode::MasternodeEntry>, Vec<masternode::MasternodeEntry>) { // (used , unused)
        match self.lookup_block_hash_by_height(block_height) {
            None => panic!("missing hash for block at height: {}", block_height),
            Some(block_hash) =>
                match self.lookup_masternode_list(block_hash) {
                    None => panic!("missing masternode list for block at height: {} with hash: {}", block_height, block_hash),
                    Some(masternode_list) => {
                        let nodes = Self::valid_masternodes_for(
                            masternode_list.masternodes,
                            Self::build_llmq_modifier(llmq_type, block_hash),
                            llmq_type.active_quorum_count(),
                            block_height);
                        let mut i: u32 = 0;
                        nodes
                            .into_iter()
                            .partition(|_| {
                                let is_true = snapshot.member_list.bit_is_true_at_le_index(i);
                                i += 1;
                                is_true
                            })
                    }
                }
        }
    }

    // Reconstruct quorum members at index from snapshot
    pub fn quorum_quarter_members_by_snapshot(
        &self,
        llmq_params: common::LLMQParams,
        quorum_base_block: common::Block,
        snapshot: llmq::LLMQSnapshot)
        -> Vec<Vec<masternode::MasternodeEntry>> {
        let llmq_type = llmq_params.r#type;
        let quorum_count = llmq_params.signing_active_quorum_count;
        let quorum_size = llmq_params.size;
        let quarter_size = (quorum_size / 4) as usize;
        let work_block_height = quorum_base_block.height - 8;
        let work_block_hash = self.lookup_block_hash_by_height(work_block_height).unwrap();
        let quorum_modifier = Self::build_llmq_modifier(llmq_params.r#type, work_block_hash);
        let (used_at_h, unused_at_h) = self.masternode_usage_by_snapshot(llmq_type, work_block_height, snapshot.clone());
        let mut sorted_combined_mns_list = Self::valid_masternodes_for_quorum(unused_at_h, quorum_modifier, quorum_count, work_block_height);
        sorted_combined_mns_list.extend(Self::valid_masternodes_for_quorum(used_at_h, quorum_modifier, quorum_count, work_block_height));
        let quorum_num = quorum_count as usize;
        let mut quarter_quorum_members = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(quorum_num);
        let skip_list = snapshot.skip_list;
        match snapshot.skip_list_mode {
            // No skipping. The skip list is empty.
            LLMQSnapshotSkipMode::NoSkipping => {
                let mut iter = sorted_combined_mns_list.iter();
                (0..quorum_num).for_each(|i| {
                    let mut quarter = Vec::<masternode::MasternodeEntry>::new();
                    while quarter.len() < quarter_size {
                        if let Some(node) = iter.next() {
                            quarter.push(node.clone());
                        } else {
                            iter = sorted_combined_mns_list.iter();
                        }
                    }
                    quarter_quorum_members.push(quarter);
                });
            },
            // Skip the first entry of the list.
            // The following entries contain the relative position of subsequent skips.
            // For example, if during the initialization phase you skip entries x, y and z of the masternode
            // list, the skip list will contain x, y-x and z-y in this mode.
            LLMQSnapshotSkipMode::SkipFirst => {
                let mut first_entry_index = 0;
                let mut processed_skip_list = Vec::<u32>::new();
                skip_list.iter().for_each(|s| {
                    let index = first_entry_index + s;
                    if first_entry_index == 0 {
                        first_entry_index = *s;
                    }
                    processed_skip_list.push(index)
                });
                let mut index: usize = 0;
                let mut idxk: usize = 0;
                (0..quorum_num).for_each(|i| {
                    let mut quarter = Vec::<masternode::MasternodeEntry>::new();
                    while quarter.len() < quarter_size {
                        if let Some(skipped) = processed_skip_list.get(idxk) {
                            idxk += 1;
                        } else if let Some(node) = sorted_combined_mns_list.get(index) {
                            quarter.push(node.clone());
                            index += 1;
                            if index == sorted_combined_mns_list.len() {
                                index = 0;
                            }
                        }
                    }
                    quarter_quorum_members.push(quarter);
                });
            },
            // Contains the entries which were not skipped.
            // This is better when there are many skips.
            // Mode 2 is more efficient and should be used when 3/4*quorumSize ≥ 1/2*masternodeNb or
            // quorumsize ≥ 2/3*masternodeNb
            LLMQSnapshotSkipMode::SkipExcept => {
                (0..quorum_num).for_each(|i| {
                    let mut quarter = Vec::<masternode::MasternodeEntry>::new();
                    skip_list.iter().for_each(|unskipped| {
                        if let Some(node) = sorted_combined_mns_list.get(*unskipped as usize) {
                            if quarter.len() < quarter_size {
                                quarter.push(node.clone());
                            }
                        }
                    });
                    quarter_quorum_members.push(quarter);
                });
            },
            LLMQSnapshotSkipMode::SkipAll => {},
        }
        quarter_quorum_members.clone()
    }

    // Determine quorum members at new index
    pub fn new_quorum_quarter_members(
        &self,
        params: common::LLMQParams,
        quorum_base_block_height: u32,
        previous_quarters: [Vec<Vec<masternode::MasternodeEntry>>; 3])
        -> Vec<Vec<masternode::MasternodeEntry>> {
        let quorum_count = params.signing_active_quorum_count;
        let num_quorums = quorum_count as usize;
        let mut quarter_quorum_members = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let quorum_size = params.size as usize;
        let quarter_size = quorum_size / 4;
        let work_block_height = quorum_base_block_height - 8;
        let work_block_hash = self.lookup_block_hash_by_height(work_block_height).unwrap();
        let modifier = Self::build_llmq_modifier(params.r#type, work_block_hash);
        match self.lookup_masternode_list(work_block_hash) {
            None => panic!("missing masternode list for height: {} / -8:{}", quorum_base_block_height, work_block_height),
            Some(masternode_list) => {
                if masternode_list.masternodes.len() < quarter_size {
                    quarter_quorum_members
                } else {
                    let mut masternodes_used_at_h = Vec::<masternode::MasternodeEntry>::new();
                    let mut masternodes_unused_at_h = Vec::<masternode::MasternodeEntry>::new();
                    let mut masternodes_used_at_h_index = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
                    (0..num_quorums).into_iter().for_each(|i| {
                        // for quarters h - c, h -2c, h -3c
                        previous_quarters.iter().for_each(|q| {
                            q.get(i).unwrap().iter().for_each(|node| {
                                if node.is_valid {
                                    masternodes_used_at_h.push(node.clone());
                                    masternodes_used_at_h_index[i].push(node.clone());
                                }
                            });
                        });
                    });
                    masternode_list.masternodes.into_values().for_each(|mn| {
                        if mn.is_valid &&
                            masternodes_unused_at_h
                                .iter()
                                .filter(|node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash)
                                .count() == 0 {
                            masternodes_unused_at_h.push(mn);
                        }
                    });
                    let mut sorted_combined_mns_list = Self::valid_masternodes_for_quorum(masternodes_unused_at_h, modifier, quorum_count, work_block_height);
                    sorted_combined_mns_list.extend(Self::valid_masternodes_for_quorum(masternodes_used_at_h, modifier, quorum_count, work_block_height));
                    let mut skip_list = Vec::<usize>::new();
                    let mut first_skipped_index = 0;
                    let mut idx = 0;
                    (0..num_quorums).for_each(|i| {
                        while quarter_quorum_members.get(i).unwrap().len() < quarter_size {
                            let mn = sorted_combined_mns_list.get(idx).unwrap();
                            if masternodes_used_at_h_index
                                .get(i)
                                .unwrap()
                                .into_iter()
                                .filter(|&node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash)
                                .count() == 0 {
                                quarter_quorum_members.get_mut(i).unwrap().push(mn.clone());
                            } else {
                                let skip_index = idx - first_skipped_index;
                                if first_skipped_index == 0 {
                                    first_skipped_index = idx;
                                }
                                skip_list.push(idx);
                            }
                            idx += 1;
                            if idx == sorted_combined_mns_list.len() {
                                idx = 0;
                            }
                        }
                    });
                    quarter_quorum_members
                }
            }
        }
    }

    pub fn quorum_members_by_quarter_rotation(
        &self,
        llmq_type: LLMQType,
        quorum_base_block_height: u32) -> Vec<Vec<masternode::MasternodeEntry>> {
        let llmq_params = llmq_type.params();
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let block_m_c_height = quorum_base_block_height - cycle_length;
        let block_m_2c_height = quorum_base_block_height - 2 * cycle_length;
        let block_m_3c_height = quorum_base_block_height - 3 * cycle_length;
        let block_m_c = common::Block { height: block_m_c_height, hash: self.lookup_block_hash_by_height(block_m_c_height).unwrap() };
        let block_m_2c = common::Block { height: block_m_2c_height, hash: self.lookup_block_hash_by_height(block_m_2c_height).unwrap() };
        let block_m_3c = common::Block { height: block_m_3c_height, hash: self.lookup_block_hash_by_height(block_m_3c_height).unwrap() };
        let q_snapshot_h_m_c = self.lookup_snapshot(block_m_c.height - 8).unwrap();
        let q_snapshot_h_m_2c = self.lookup_snapshot(block_m_2c.height - 8).unwrap();
        let q_snapshot_h_m_3c = self.lookup_snapshot(block_m_3c.height - 8).unwrap();
        let prev_q_h_m_c = self.quorum_quarter_members_by_snapshot(llmq_params, block_m_c, q_snapshot_h_m_c);
        let prev_q_h_m_2c = self.quorum_quarter_members_by_snapshot(llmq_params, block_m_2c, q_snapshot_h_m_2c);
        let prev_q_h_m_3c = self.quorum_quarter_members_by_snapshot(llmq_params, block_m_3c, q_snapshot_h_m_3c);
        let mut quorum_members = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let new_quarter_members = self.new_quorum_quarter_members(llmq_params, quorum_base_block_height, [prev_q_h_m_c.clone(), prev_q_h_m_2c.clone(), prev_q_h_m_3c.clone()]);
        (0..num_quorums).for_each(|i| {
            Self::add_quorum_members_from_quarter(&mut quorum_members, &prev_q_h_m_3c, i);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &prev_q_h_m_2c, i);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &prev_q_h_m_c, i);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &new_quarter_members, i);
        });
        quorum_members
    }

    fn add_quorum_members_from_quarter(quorum_members: &mut Vec<Vec<masternode::MasternodeEntry>>, quarter: &Vec<Vec<masternode::MasternodeEntry>>, index: usize) {
        if let Some(indexed_quarter) = quarter.get(index) {
            indexed_quarter.iter().for_each(|member| {
                if let Some(quarter_members) = quorum_members.get_mut(index) {
                    quarter_members.push(member.clone());
                } else {
                    quorum_members.insert(index, vec![member.clone()]);
                }
            })
        }
    }

    // Determine masternodes which is responsible for signing at this quorum index
    pub fn get_rotated_masternodes_for_quorum(&self,
                                              llmq_type: LLMQType,
                                              llmq_base_block_hash: UInt256,
                                              llmq_base_block_height: u32,
                                              cache: &mut MasternodeProcessorCache)
        -> Vec<masternode::MasternodeEntry> {
        let map_quorum_members = &mut cache.map_quorum_members;
        let map_indexed_quorum_members = &mut cache.map_indexed_quorum_members;
        let map_by_type_opt = map_quorum_members.get_mut(&llmq_type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&llmq_base_block_hash) {
                return members.clone();
            }
        }
        let map_by_type = map_by_type_opt.unwrap();
        let mut quorum_members = Vec::<masternode::MasternodeEntry>::new();
        let quorum_index = llmq_base_block_height % llmq_type.params().dkg_params.interval;
        let cycle_quorum_base_block_height = llmq_base_block_height - quorum_index;
        let cycle_quorum_base_block_hash = self.lookup_block_hash_by_height(cycle_quorum_base_block_height).unwrap();
        if let Some(map_by_type_indexed) = map_indexed_quorum_members.get(&llmq_type) {
            let cycle_indexed_hash = llmq::LLMQIndexedHash { hash: cycle_quorum_base_block_hash, index: quorum_index };
            if let Some(indexed_members) = map_by_type_indexed.get(&cycle_indexed_hash) {
                quorum_members = indexed_members.clone();
                map_by_type.insert(cycle_quorum_base_block_hash, quorum_members.clone());
                return quorum_members;
            }
        }
        let rotated_members = self.quorum_members_by_quarter_rotation(llmq_type, cycle_quorum_base_block_height);
        let map_indexed_quorum_members_of_type = map_indexed_quorum_members.get_mut(&llmq_type).unwrap();
        rotated_members.iter().enumerate().for_each(|(i, members)| {
            map_indexed_quorum_members_of_type.insert(llmq::LLMQIndexedHash { hash: cycle_quorum_base_block_hash, index: i as u32 }, members.clone());
        });
        if let Some(members) = rotated_members.get(quorum_index as usize) {
            quorum_members = members.clone();
            map_by_type.insert(llmq_base_block_hash, quorum_members.clone());
        }
        quorum_members
    }


    ///////////////////////////////////////////////////////////////////////////////////////////

    fn lookup_masternodes_and_quorums_for(&self, block_hash: Option<UInt256>)
        -> (BTreeMap<UInt256, masternode::MasternodeEntry>,
            BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>) {
        if let Some(block_hash) = block_hash {
            if let Some(list) = self.lookup_masternode_list(block_hash) {
                return (list.masternodes, list.quorums);
            }
        }
        (BTreeMap::new(), BTreeMap::new())
    }

    pub fn lookup_masternode_list(&self, block_hash: UInt256) -> Option<masternode::MasternodeList> {
        println!("lookup_masternode_list: {} {:?}", block_hash, self.context);
        callbacks::lookup_masternode_list(
            block_hash,
            |h: UInt256| unsafe { (self.get_masternode_list_by_block_hash)(boxed(h.0), self.context) },
            |list: *const types::MasternodeList| unsafe { (self.destroy_masternode_list)(list) }
        )
    }

    pub fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<UInt256> {
        println!("lookup_block_hash_by_height: {:?} {:?}", block_height, self.context);
        callbacks::lookup_block_hash_by_height(block_height, |h: u32| unsafe { (self.get_block_hash_by_height)(h, self.context) })
    }

    pub fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
        println!("lookup_block_height_by_hash: {:?} {:?}", block_hash, self.context);
        unsafe { (self.get_block_height_by_hash)(boxed(block_hash.0), self.context) }
    }

    pub fn lookup_snapshot<'a>(&self, block_height: u32) -> Option<llmq::LLMQSnapshot<'a>> {
        callbacks::lookup_snapshot(block_height, |h: u32| unsafe { (self.get_llmq_snapshot_by_block_height)(h, self.context) })
    }

    pub fn should_process_quorum(&self, llmq_type: LLMQType) -> bool {
        unsafe { (self.should_process_llmq_of_type)(llmq_type.into(), self.context) }
    }

    pub fn add_insight(&self, block_hash: UInt256) {
        unsafe { (self.add_insight)(boxed(block_hash.0), self.context) }
    }

    fn validate_signature(&self, valid_masternodes: Vec<masternode::MasternodeEntry>, mut quorum: masternode::LLMQEntry, block_height: u32, mut has_valid_quorums: bool) {
        let operator_pks: Vec<*mut [u8; 48]> = (0..valid_masternodes.len())
            .into_iter()
            .filter_map(|i| match quorum.signers_bitset.bit_is_true_at_le_index(i as u32) {
                true => Some(boxed(valid_masternodes[i].operator_public_key_at(block_height).0)),
                false => None
            })
            .collect();

        let operator_public_keys_count = operator_pks.len();
        let is_valid_signature = unsafe { (self.validate_llmq)(boxed(types::LLMQValidationData {
            items: boxed_vec(operator_pks),
            count: operator_public_keys_count,
            commitment_hash: boxed(quorum.generate_commitment_hash().0),
            all_commitment_aggregated_signature: boxed(quorum.all_commitment_aggregated_signature.0),
            threshold_signature: boxed(quorum.threshold_signature.0),
            public_key: boxed(quorum.public_key.0)
        }), self.context) };
        has_valid_quorums &= quorum.validate_payload() && is_valid_signature;
        if has_valid_quorums {
            quorum.verified = true;
        }
    }
}
