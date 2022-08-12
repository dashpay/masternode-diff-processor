use std::cmp::min;
use std::collections::{BTreeMap, HashSet};
use std::ptr::null;
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetLLMQSnapshotByBlockHash, MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup, SaveLLMQSnapshot, ShouldProcessLLMQTypeCallback, ValidateLLMQCallback};
use dash_spv_ffi::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use dash_spv_ffi::types;
use dash_spv_ffi::ffi::callbacks;
use dash_spv_models::common::{LLMQParams, LLMQType};
use dash_spv_models::{common, llmq, masternode};
use dash_spv_primitives::consensus::{Encodable, encode};
use dash_spv_primitives::crypto::byte_util::{Reversable, Zeroable};
use dash_spv_primitives::crypto::data_ops::{Data, inplace_intersection};
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::{Hash, sha256d};
use crate::processing::MNListDiffResult;
use crate::processing::processor_cache::MasternodeProcessorCache;

#[derive(Copy, Clone, Debug)]
pub struct ProcessorContext {
    pub use_insight_as_backup: bool,
}

// https://github.com/rust-lang/rfcs/issues/2770
#[repr(C)]
pub struct MasternodeProcessor {
    /// External Masternode Manager Diff Message Context
    pub context: *const std::ffi::c_void,
    pub get_block_height_by_hash: GetBlockHeightByHash,
    pub get_merkle_root_by_hash: MerkleRootLookup,
    get_block_hash_by_height: GetBlockHashByHeight,
    get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
    save_llmq_snapshot: SaveLLMQSnapshot,
    get_masternode_list_by_block_hash: MasternodeListLookup,
    save_masternode_list: MasternodeListSave,
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
        get_merkle_root_by_hash: MerkleRootLookup,
        get_block_height_by_hash: GetBlockHeightByHash,
        get_block_hash_by_height: GetBlockHashByHeight,
        get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
        save_llmq_snapshot: SaveLLMQSnapshot,
        get_masternode_list_by_block_hash: MasternodeListLookup,
        save_masternode_list: MasternodeListSave,
        destroy_masternode_list: MasternodeListDestroy,
        add_insight: AddInsightBlockingLookup,
        should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
        validate_llmq: ValidateLLMQCallback/*,
        context: *const std::ffi::c_void*/) -> Self {
        Self {
            get_merkle_root_by_hash,
            get_block_height_by_hash,
            get_block_hash_by_height,
            get_llmq_snapshot_by_block_hash,
            save_llmq_snapshot,
            get_masternode_list_by_block_hash,
            save_masternode_list,
            destroy_masternode_list,
            add_insight,
            should_process_llmq_of_type,
            validate_llmq,
            context: null(),
        }
    }

    pub(crate) fn find_masternode_list(&self, block_hash: UInt256, cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>) -> Option<masternode::MasternodeList> {
        if let Some(cached) = cached_lists.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            println!("find_masternode_list: (Cached) {}", block_hash);
            Some(cached.clone())
        } else if let Some(looked) = self.lookup_masternode_list(block_hash) {
            // Getting it from FFI directly
            println!("find_masternode_list: (Looked) {}", block_hash);
            Some(looked)
        } else {
            println!("find_masternode_list: (None) {}", block_hash);
            None
        }
    }
    pub(crate) fn find_snapshot(&self, block_hash: UInt256, cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>) -> Option<llmq::LLMQSnapshot> {
        if let Some(cached) = cached_snapshots.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            println!("find_snapshot: (Cached) {}", block_hash);
            Some(cached.clone())
        } else if let Some(looked) = self.lookup_snapshot_by_block_hash(block_hash) {
            // Getting it from FFI directly
            println!("find_snapshot: (Looked) {}", block_hash);
            Some(looked)
        } else {
            println!("find_snapshot: (None) {}", block_hash);
            None
        }
    }



    pub(crate) fn get_list_diff_result_with_base_lookup(&self,
                                       list_diff: llmq::MNListDiff,
                                       processor_context: ProcessorContext,
                                       cache: &mut MasternodeProcessorCache)
                                       -> types::MNListDiffResult {
        let base_list = self.find_masternode_list(list_diff.base_block_hash, &cache.mn_lists);
        self.get_list_diff_result(base_list, list_diff, processor_context, cache)
    }


    pub(crate) fn get_list_diff_result_internal_with_base_lookup(&self,
                                                        list_diff: llmq::MNListDiff,
                                                        processor_context: ProcessorContext,
                                                        cache: &mut MasternodeProcessorCache)
                                                        -> MNListDiffResult {
        let base_list = self.find_masternode_list(list_diff.base_block_hash, &cache.mn_lists);
        self.get_list_diff_result_internal(base_list, list_diff, processor_context, cache)
    }

    pub(crate) fn get_list_diff_result(&self,
                                       base_list: Option<masternode::MasternodeList>,
                                       list_diff: llmq::MNListDiff,
                                       processor_context: ProcessorContext,
                                       cache: &mut MasternodeProcessorCache)
        -> types::MNListDiffResult {
        let result = self.get_list_diff_result_internal(base_list, list_diff, processor_context, cache);
        // println!("get_list_diff_result: {:#?}", result);
        types::MNListDiffResult {
            block_hash: boxed(result.block_hash.0),
            has_found_coinbase: result.has_found_coinbase,
            has_valid_coinbase: result.has_valid_coinbase,
            has_valid_mn_list_root: result.has_valid_mn_list_root,
            has_valid_llmq_list_root: result.has_valid_llmq_list_root,
            has_valid_quorums: result.has_valid_quorums,
            masternode_list: boxed(result.masternode_list.encode()),
            added_masternodes: encode_masternodes_map(&result.added_masternodes),
            added_masternodes_count: result.added_masternodes.len(),
            modified_masternodes: encode_masternodes_map(&result.modified_masternodes),
            modified_masternodes_count: result.modified_masternodes.len(),
            added_llmq_type_maps: encode_quorums_map(&result.added_quorums),
            added_llmq_type_maps_count: result.added_quorums.len(),
            needed_masternode_lists: boxed_vec(result.needed_masternode_lists.iter().map(|h|boxed(h.0)).collect()),
            needed_masternode_lists_count: result.needed_masternode_lists.len()
        }

    }

    fn cache_masternode_list(&self, block_hash: UInt256, list: masternode::MasternodeList, cache: &mut MasternodeProcessorCache) {
        // It's good to cache lists to use it inside processing session
        // Here we use opaque-like pointer which we initiate on the C-side to sync its lifetime with runtime
        cache.add_masternode_list(block_hash, list);
        // Here we just store it in the C-side ()
        // self.save_masternode_list(block_hash, &masternode_list);
    }

    pub(crate) fn get_list_diff_result_internal(&self,
                                       base_list: Option<masternode::MasternodeList>,
                                       list_diff: llmq::MNListDiff,
                                       processor_context: ProcessorContext,
                                       cache: &mut MasternodeProcessorCache)
                                       -> MNListDiffResult {
        let block_hash = list_diff.block_hash;
        let block_height = list_diff.block_height;
        println!("get_list_diff_result_internal: {}: {}", block_height, block_hash);
        let (base_masternodes,
            base_quorums) = match base_list {
            Some(list) => (list.masternodes, list.quorums),
            None => (BTreeMap::new(), BTreeMap::new())
        };
        let mut coinbase_transaction = list_diff.coinbase_transaction;
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
        let masternode_list = masternode::MasternodeList::new(masternodes, quorums, block_hash, block_height, quorums_active);
        let merkle_tree = common::MerkleTree { tree_element_count: list_diff.total_transactions, hashes: list_diff.merkle_hashes.1, flags: list_diff.merkle_flags };
        self.cache_masternode_list(block_hash, masternode_list.clone(), cache);

        MNListDiffResult {
            block_hash,
            has_found_coinbase: coinbase_transaction.has_found_coinbase(&merkle_tree.hashes),
            has_valid_coinbase: merkle_tree.has_root(self.lookup_merkle_root_by_hash(block_hash).unwrap_or(UInt256::MIN)),
            has_valid_mn_list_root: masternode_list.has_valid_mn_list_root(&coinbase_transaction),
            has_valid_llmq_list_root: !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction),
            has_valid_quorums,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            added_quorums,
            needed_masternode_lists
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
                            cache: &mut MasternodeProcessorCache)
                            -> (BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
                                BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
                                bool,
                                Vec<UInt256>) {
        let has_valid_quorums = true;
        let mut needed_masternode_lists: Vec<UInt256> = Vec::new();
        let mut added = added_quorums.clone();
        added
            .iter_mut()
            .for_each(|(&llmq_type, llmqs_of_type)| {
                if self.should_process_quorum(llmq_type) {
                    (*llmqs_of_type).iter_mut().for_each(|(&llmq_block_hash, quorum)| {
                        match self.find_masternode_list(llmq_block_hash, &cache.mn_lists) {
                            Some(llmq_masternode_list) =>
                                self.validate_quorum(
                                    quorum,
                                    has_valid_quorums,
                                    llmq_block_hash,
                                    llmq_masternode_list.masternodes,
                                    processor_context,
                                    cache
                                ),
                            None =>
                                if self.lookup_block_height_by_hash(llmq_block_hash) != u32::MAX {
                                    needed_masternode_lists.push(llmq_block_hash);
                                } else if processor_context.use_insight_as_backup {
                                    self.add_insight(llmq_block_hash);
                                    if self.lookup_block_height_by_hash(llmq_block_hash) != u32::MAX {
                                        needed_masternode_lists.push(llmq_block_hash);
                                    }
                                }
                        }
                    });
                }
            });
        let mut quorums = base_quorums.clone();
        quorums.extend(added
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
            if let Some(keys_to_add) = added.get(llmq_type) {
                keys_to_add.clone().into_iter().for_each(|(key, entry)| {
                    (*llmq_map).insert(key, entry);
                });
            }
        });
        //println!("classify_quorums: valid: {}, added: {:#?}, quorums: {:#?}", has_valid_quorums, added, quorums, );
        (added, quorums, has_valid_quorums, needed_masternode_lists)
    }

    pub fn validate_quorum(
        &self,
        quorum: &mut masternode::LLMQEntry,
        has_valid_quorums: bool,
        block_hash: UInt256,
        masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        processor_context: ProcessorContext,
        cache: &mut MasternodeProcessorCache,
    ) {
        let block_height = self.lookup_block_height_by_hash(block_hash);
        let quorum_modifier = quorum.llmq_quorum_hash();
        let quorum_count = quorum.llmq_type.size();
        println!("validate_quorum: {}:{} {:?}:{}:{:?}", block_height, block_hash, quorum.llmq_type, quorum.llmq_hash, quorum.index);
        let valid_masternodes = if quorum.index.is_some() {
            self.get_rotated_masternodes_for_quorum(
                quorum.llmq_type,
                block_hash,
                block_height,
                cache
            )
        } else {
            Self::valid_masternodes_for(masternodes, quorum_modifier, quorum_count, block_height)
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

    // Reconstruct quorum members at index from snapshot
    pub fn quorum_quarter_members_by_snapshot(
        &self,
        llmq_params: LLMQParams,
        quorum_base_block_height: u32,
        cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>)
        -> Vec<Vec<masternode::MasternodeEntry>> {
        let work_block_height = quorum_base_block_height - 8;
        let llmq_type = llmq_params.r#type;
        let quorum_count = llmq_params.signing_active_quorum_count;
        let quorum_size = llmq_params.size;
        let quarter_size = (quorum_size / 4) as usize;
        // Quorum members dichotomy in snapshot
        match self.lookup_block_hash_by_height(work_block_height) {
            None => panic!("missing hash for block at height: {}", work_block_height),
            Some(work_block_hash) =>
                match self.find_snapshot(work_block_hash, &cached_snapshots) {
                    None => panic!("missing snapshot for block at height: {}", work_block_height),
                    Some(snapshot) => {
                        let quorum_modifier = Self::build_llmq_modifier(llmq_type, work_block_hash);
                        let (used_at_h, unused_at_h) = match self.find_masternode_list(work_block_hash, &cached_lists) {
                            None => panic!("missing masternode_list for block at height: {} with hash: {}", work_block_height, work_block_hash),
                            Some(masternode_list) => {
                                let nodes = Self::valid_masternodes_for(
                                    masternode_list.masternodes,
                                    quorum_modifier,
                                    quorum_count,
                                    work_block_height);
                                let mut i: u32 = 0;
                                // TODO: partition with enumeration doesn't work here (why?)
                                nodes
                                    .into_iter()
                                    .partition(|_| {
                                        let is_true = snapshot.member_list.bit_is_true_at_le_index(i);
                                        i += 1;
                                        is_true
                                    })
                            }
                        };
                        let mut sorted_combined_mns_list = Self::valid_masternodes_for_quorum(
                            unused_at_h, quorum_modifier, quorum_count, work_block_height);
                        sorted_combined_mns_list.extend(Self::valid_masternodes_for_quorum(
                            used_at_h, quorum_modifier, quorum_count, work_block_height));

                        snapshot.apply_skip_strategy(sorted_combined_mns_list, quorum_count as usize, quarter_size)
                    }
                }
        }
    }

    // Determine quorum members at new index
    pub fn new_quorum_quarter_members(
        &self,
        params: LLMQParams,
        quorum_base_block_height: u32,
        previous_quarters: [Vec<Vec<masternode::MasternodeEntry>>; 3])
        -> Vec<Vec<masternode::MasternodeEntry>> {
        let quorum_count = params.signing_active_quorum_count;
        let num_quorums = quorum_count as usize;
        let mut quarter_quorum_members = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let quorum_size = params.size as usize;
        let quarter_size = quorum_size / 4;
        let work_block_height = quorum_base_block_height - 8;

        match self.lookup_block_hash_by_height(work_block_height) {
            None => panic!("missing block for height: {}", work_block_height),
            Some(work_block_hash) =>
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
                            let modifier = Self::build_llmq_modifier(params.r#type, work_block_hash);
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

    fn rotate_members(&self, cycle_quorum_base_block_height: u32, llmq_params: LLMQParams,
                      cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
                      cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>) -> Vec<Vec<masternode::MasternodeEntry>> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let prev_q_h_m_c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - cycle_length,
            cached_lists,
            cached_snapshots);
        let prev_q_h_m_2c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - 2 * cycle_length,
            cached_lists,
            cached_snapshots);
        let prev_q_h_m_3c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - 3 * cycle_length,
            cached_lists,
            cached_snapshots);

        let mut rotated_members = Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let new_quarter_members = self.new_quorum_quarter_members(
            llmq_params,
            cycle_quorum_base_block_height,
            [
                prev_q_h_m_c.clone(),
                prev_q_h_m_2c.clone(),
                prev_q_h_m_3c.clone()
            ]);
        (0..num_quorums).for_each(|i| {
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_3c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_2c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &new_quarter_members, i);
        });
        rotated_members
    }

    /// Determine masternodes which is responsible for signing at this quorum index
    pub fn get_rotated_masternodes_for_quorum(&self,
                                              llmq_type: LLMQType,
                                              llmq_base_hash: UInt256,
                                              llmq_base_block_height: u32,
                                              cache: &mut MasternodeProcessorCache)
                                              -> Vec<masternode::MasternodeEntry> {
        let map_by_type_opt = cache.llmq_members.get_mut(&llmq_type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&llmq_base_hash) {
                return members.clone();
            }
        } else {
            cache.llmq_members.insert(llmq_type, BTreeMap::new());
        }
        let map_by_type = cache.llmq_members.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = llmq_base_block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = llmq_base_block_height - quorum_index;
        match self.lookup_block_hash_by_height(cycle_base_height) {
            None => panic!("missing hash for block at height: {}", cycle_base_height),
            Some(cycle_base_hash) => {
                let map_by_type_indexed_opt = cache.llmq_indexed_members.get_mut(&llmq_type);
                if let Some(ref map_by_type_indexed) = map_by_type_indexed_opt {
                    if let Some(members) = map_by_type_indexed.get(&llmq::LLMQIndexedHash::new(cycle_base_hash, quorum_index)) {
                        map_by_type.insert(llmq_base_hash, members.clone());
                        return members.clone();
                    }
                }
                let rotated_members = self.rotate_members(cycle_base_height, llmq_params, &cache.mn_lists, &cache.llmq_snapshots);

                let map_indexed_quorum_members_of_type = map_by_type_indexed_opt.unwrap();
                rotated_members.iter().enumerate().for_each(|(i, members)| {
                    map_indexed_quorum_members_of_type.insert(llmq::LLMQIndexedHash::new(cycle_base_hash, i as u32), members.clone());
                });
                if let Some(members) = rotated_members.get(quorum_index as usize) {
                    map_by_type.insert(llmq_base_hash, members.clone());
                    return members.clone();
                }
                vec![]
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    /// FFI-callbacks
    ///////////////////////////////////////////////////////////////////////////////////////////

    pub fn lookup_masternode_list(&self, block_hash: UInt256) -> Option<masternode::MasternodeList> {
        // First look at the local cache
        let result = callbacks::lookup_masternode_list(
            block_hash,
            |h: UInt256| unsafe { (self.get_masternode_list_by_block_hash)(boxed(h.0), self.context) },
            |list: *const types::MasternodeList| unsafe { (self.destroy_masternode_list)(list) }
        );
        if let Some(result) = &result {
            println!("lookup_masternode_list (Some): {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash);
        } else {
            println!("lookup_masternode_list (None): {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash);
        }
        result
    }

    pub fn save_masternode_list(&self, block_hash: UInt256, masternode_list: &masternode::MasternodeList) -> bool {
        println!("save_masternode_list: {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash);
        unsafe { (self.save_masternode_list)(boxed(block_hash.0), boxed(masternode_list.encode()), self.context) }
    }

    pub fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<UInt256> {
        println!("lookup_block_hash_by_height: {:?} {:?}", block_height, self.context);
        callbacks::lookup_block_hash_by_height(block_height, |h: u32| unsafe { (self.get_block_hash_by_height)(h, self.context) })
    }

    pub fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
        // println!("lookup_block_height_by_hash: {:?} {:?}", block_hash, self.context);
        unsafe { (self.get_block_height_by_hash)(boxed(block_hash.0), self.context) }
    }

    pub fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Option<llmq::LLMQSnapshot> {
        callbacks::lookup_snapshot_by_block_hash(block_hash, |h: UInt256| unsafe { (self.get_llmq_snapshot_by_block_hash)(boxed(h.0), self.context) })
    }

    pub fn save_snapshot(&self, block_hash: UInt256, snapshot: llmq::LLMQSnapshot) -> bool {
        println!("save_snapshot: {}: {:?} {:?}", block_hash, snapshot, self.context);
        unsafe { (self.save_llmq_snapshot)(boxed(block_hash.0), boxed(snapshot.encode()), self.context) }
    }

    pub fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Option<UInt256> {
        callbacks::lookup_merkle_root_by_hash(block_hash, |h: UInt256| unsafe { (self.get_merkle_root_by_hash)(boxed(h.0), self.context) })
    }

    pub fn should_process_quorum(&self, llmq_type: LLMQType) -> bool {
        unsafe { (self.should_process_llmq_of_type)(llmq_type.into(), self.context) }
    }

    pub fn add_insight(&self, block_hash: UInt256) {
        unsafe { (self.add_insight)(boxed(block_hash.0), self.context) }
    }

    /// Calls c++ BLS lib via FFI
    fn validate_signature(&self, valid_masternodes: Vec<masternode::MasternodeEntry>, quorum: &mut masternode::LLMQEntry, block_height: u32, mut has_valid_quorums: bool) {
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
        let is_valid_payload = quorum.validate_payload();
        has_valid_quorums &= is_valid_payload && is_valid_signature;
        println!("validate_signature: {}: signature: {} payload: {}, has_valid_quorums: {}", quorum.llmq_hash, is_valid_signature, is_valid_payload, has_valid_quorums);
        if has_valid_quorums {
            quorum.verified = true;
        }
    }

    pub fn read_list_diff_from_message<'a>(&self, message: &'a [u8], offset: &mut usize) -> Option<llmq::MNListDiff<'a>> {
        llmq::MNListDiff::new(
            message,
            offset,
            |hash|
                self.lookup_block_height_by_hash(hash))
    }

}
