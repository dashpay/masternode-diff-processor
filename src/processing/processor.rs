use crate::processing::processor_cache::MasternodeProcessorCache;
use crate::processing::{MNListDiffResult, ProcessingError};
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::callbacks;
use dash_spv_ffi::ffi::callbacks::{
    AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash,
    GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, LogMessage,
    MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup,
    SaveLLMQSnapshot, ShouldProcessDiffWithRange, ShouldProcessLLMQTypeCallback,
    ValidateLLMQCallback,
};
use dash_spv_ffi::ffi::to::ToFFI;
use dash_spv_ffi::types;
use dash_spv_models::common::{LLMQParams, LLMQType};
use dash_spv_models::{common, llmq, masternode};
use dash_spv_primitives::consensus::{encode, Encodable};
use dash_spv_primitives::crypto::byte_util::{ConstDecodable, Reversable, Zeroable};
use dash_spv_primitives::crypto::data_ops::{inplace_intersection, Data};
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::{sha256d, Hash};
use std::cmp::min;
use std::collections::{BTreeMap, HashSet};
use std::ptr::null;

// https://github.com/rust-lang/rfcs/issues/2770
#[repr(C)]
pub struct MasternodeProcessor {
    /// External Masternode Manager Diff Message Context
    pub opaque_context: *const std::ffi::c_void,
    pub genesis_hash: *const u8,
    pub use_insight_as_backup: bool,
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
    destroy_hash: HashDestroy,
    destroy_snapshot: LLMQSnapshotDestroy,
    should_process_diff_with_range: ShouldProcessDiffWithRange,
    log_message: LogMessage,
}
impl std::fmt::Debug for MasternodeProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeProcessor")
            .field("context", &self.opaque_context)
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
        validate_llmq: ValidateLLMQCallback,
        destroy_hash: HashDestroy,
        destroy_snapshot: LLMQSnapshotDestroy,
        should_process_diff_with_range: ShouldProcessDiffWithRange,
        log_message: LogMessage,
        /*opaque_context: *const std::ffi::c_void*/
    ) -> Self {
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
            destroy_hash,
            destroy_snapshot,
            should_process_diff_with_range,
            log_message,
            opaque_context: null(),
            genesis_hash: null(),
            use_insight_as_backup: false,
        }
    }

    pub(crate) fn find_masternode_list(
        &self,
        block_hash: UInt256,
        cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        unknown_lists: &mut Vec<UInt256>,
    ) -> Option<masternode::MasternodeList> {
        let genesis_hash = UInt256::from_const(self.genesis_hash).unwrap();
        if block_hash.is_zero() {
            // If it's a zero block we don't expect masternode list here
            self.log(format!(
                "find_masternode_list: (None: It's a zero hash) {}: {}",
                UInt256::MAX,
                block_hash
            ));
            None
        } else if block_hash.eq(&genesis_hash) {
            // If it's a genesis block we don't expect masternode list here
            self.log(format!(
                "find_masternode_list: (None: It's a genesis) {}: {}",
                self.lookup_block_height_by_hash(block_hash),
                block_hash
            ));
            Some(masternode::MasternodeList::new(BTreeMap::default(), BTreeMap::default(), block_hash, self.lookup_block_height_by_hash(block_hash), false))
            // None
        } else if let Some(cached) = cached_lists.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            self.log(format!(
                "find_masternode_list: (Cached) {}: {}",
                self.lookup_block_height_by_hash(block_hash),
                block_hash
            ));
            Some(cached.clone())
        } else if let Some(looked) = self.lookup_masternode_list(block_hash) {
            // Getting it from FFI directly
            self.log(format!(
                "find_masternode_list: (Looked) {}: {}",
                self.lookup_block_height_by_hash(block_hash),
                block_hash
            ));
            Some(looked)
        } else {
            //self.log(format!("find_masternode_list: (None) {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash));
            if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                unknown_lists.push(block_hash);
            } else if self.use_insight_as_backup {
                self.add_insight(block_hash);
                if self.lookup_block_height_by_hash(block_hash) != u32::MAX {
                    unknown_lists.push(block_hash);
                }
            }
            None
        }
    }
    pub(crate) fn find_snapshot(
        &self,
        block_hash: UInt256,
        cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>,
    ) -> Option<llmq::LLMQSnapshot> {
        if let Some(cached) = cached_snapshots.get(&block_hash) {
            // Getting it from local cache stored as opaque in FFI context
            self.log(format!("find_snapshot: (Cached) {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash));
            Some(cached.clone())
        } else if let Some(looked) = self.lookup_snapshot_by_block_hash(block_hash) {
            // Getting it from FFI directly
            self.log(format!("find_snapshot: (Looked) {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash));
            Some(looked)
        } else {
            self.log(format!("find_snapshot: (None) {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash));
            None
        }
    }

    pub(crate) fn get_list_diff_result_with_base_lookup(
        &self,
        list_diff: llmq::MNListDiff,
        cache: &mut MasternodeProcessorCache,
    ) -> types::MNListDiffResult {
        let base_block_hash = list_diff.base_block_hash;
        let base_list = self.find_masternode_list(
            base_block_hash,
            &cache.mn_lists,
            &mut cache.needed_masternode_lists,
        );
        self.get_list_diff_result(base_list, list_diff, cache)
    }

    pub(crate) fn get_list_diff_result_internal_with_base_lookup(
        &self,
        list_diff: llmq::MNListDiff,
        cache: &mut MasternodeProcessorCache,
    ) -> MNListDiffResult {
        let base_list = self.find_masternode_list(
            list_diff.base_block_hash,
            &cache.mn_lists,
            &mut cache.needed_masternode_lists,
        );
        self.get_list_diff_result_internal(base_list, list_diff, cache)
    }

    pub(crate) fn get_list_diff_result(
        &self,
        base_list: Option<masternode::MasternodeList>,
        list_diff: llmq::MNListDiff,
        cache: &mut MasternodeProcessorCache,
    ) -> types::MNListDiffResult {
        let result = self.get_list_diff_result_internal(base_list, list_diff, cache);
        result.encode()
    }

    fn cache_masternode_list(
        &self,
        block_hash: UInt256,
        list: masternode::MasternodeList,
        cache: &mut MasternodeProcessorCache,
    ) {
        // It's good to cache lists to use it inside processing session
        // Here we use opaque-like pointer which we initiate on the C-side to sync its lifetime with runtime
        cache.add_masternode_list(block_hash, list);
        // Here we just store it in the C-side ()
        // self.save_masternode_list(block_hash, &masternode_list);
    }

    pub(crate) fn get_list_diff_result_internal(
        &self,
        base_list: Option<masternode::MasternodeList>,
        list_diff: llmq::MNListDiff,
        cache: &mut MasternodeProcessorCache,
    ) -> MNListDiffResult {
        let base_block_hash = list_diff.base_block_hash;
        let block_hash = list_diff.block_hash;
        let block_height = list_diff.block_height;
        let (base_masternodes, base_quorums) = match base_list {
            Some(list) => (list.masternodes, list.quorums),
            None => (BTreeMap::new(), BTreeMap::new()),
        };
        let mut coinbase_transaction = list_diff.coinbase_transaction;
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (added_masternodes, modified_masternodes, masternodes) = self.classify_masternodes(
            base_masternodes,
            list_diff.added_or_modified_masternodes,
            list_diff.deleted_masternode_hashes,
            block_height,
            block_hash,
        );
        let (added_quorums, quorums, has_valid_quorums) = self.classify_quorums(
            base_quorums,
            list_diff.added_quorums,
            list_diff.deleted_quorums,
            cache,
        );
        let masternode_list = masternode::MasternodeList::new(
            masternodes,
            quorums,
            block_hash,
            block_height,
            quorums_active,
        );
        let merkle_tree = common::MerkleTree {
            tree_element_count: list_diff.total_transactions,
            hashes: list_diff.merkle_hashes.1,
            flags: list_diff.merkle_flags.as_slice(),
        };
        self.cache_masternode_list(block_hash, masternode_list.clone(), cache);
        let needed_masternode_lists = cache.needed_masternode_lists.clone();
        cache.needed_masternode_lists.clear();
        MNListDiffResult {
            error_status: ProcessingError::None,
            base_block_hash,
            block_hash,
            has_found_coinbase: coinbase_transaction.has_found_coinbase(&merkle_tree.hashes),
            has_valid_coinbase: merkle_tree.has_root(
                self.lookup_merkle_root_by_hash(block_hash)
                    .unwrap_or(UInt256::MIN),
            ),
            has_valid_mn_list_root: masternode_list.has_valid_mn_list_root(&coinbase_transaction),
            has_valid_llmq_list_root: !quorums_active
                || masternode_list.has_valid_llmq_list_root(&coinbase_transaction),
            has_valid_quorums,
            masternode_list,
            added_masternodes,
            modified_masternodes,
            added_quorums,
            needed_masternode_lists,
        }
    }

    pub fn classify_masternodes(
        &self,
        base_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        added_or_modified_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        deleted_masternode_hashes: Vec<UInt256>,
        block_height: u32,
        block_hash: UInt256,
    ) -> (
        BTreeMap<UInt256, masternode::MasternodeEntry>,
        BTreeMap<UInt256, masternode::MasternodeEntry>,
        BTreeMap<UInt256, masternode::MasternodeEntry>,
    ) {
        let added_or_modified_masternodes = added_or_modified_masternodes;
        let deleted_masternode_hashes = deleted_masternode_hashes;
        let mut added_masternodes = added_or_modified_masternodes.clone();
        let mut modified_masternode_keys: HashSet<UInt256> = HashSet::new();
        if base_masternodes.len() > 0 {
            let base_masternodes = base_masternodes.clone();
            base_masternodes.iter().for_each(|(h, _e)| {
                added_masternodes.remove(h);
            });
            let mut new_mn_keys: HashSet<UInt256> =
                added_or_modified_masternodes.keys().cloned().collect();
            let mut old_mn_keys: HashSet<UInt256> = base_masternodes.keys().cloned().collect();
            modified_masternode_keys = inplace_intersection(&mut new_mn_keys, &mut old_mn_keys);
        }
        let mut modified_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry> =
            modified_masternode_keys
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
        modified_masternodes
            .iter_mut()
            .for_each(|(hash, modified)| {
                if let Some(mut old) = masternodes.get_mut(hash) {
                    if (*old).update_height < (*modified).update_height {
                        if (*modified).provider_registration_transaction_hash
                            == (*old).provider_registration_transaction_hash
                        {
                            (*modified).update_with_previous_entry(
                                old,
                                common::Block {
                                    height: block_height,
                                    hash: block_hash,
                                },
                            );
                        }
                        if !(*old).confirmed_hash.is_zero()
                            && (*old).known_confirmed_at_height.is_some()
                            && (*old).known_confirmed_at_height.unwrap() > block_height
                        {
                            (*old).known_confirmed_at_height = Some(block_height);
                        }
                    }
                    masternodes.insert((*hash).clone(), (*modified).clone());
                }
            });
        (added_masternodes, modified_masternodes, masternodes)
    }

    pub fn classify_quorums(
        &self,
        base_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
        added_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
        deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>>,
        cache: &mut MasternodeProcessorCache,
    ) -> (
        BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
        BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>,
        bool,
    ) {
        let has_valid_quorums = true;
        let mut added = added_quorums.clone();
        added.iter_mut().for_each(|(&llmq_type, llmqs_of_type)| {
            if self.should_process_quorum(llmq_type) {
                (*llmqs_of_type)
                    .iter_mut()
                    .for_each(|(&llmq_block_hash, quorum)| {
                        if let Some(masternode::MasternodeList { masternodes, .. }) = self
                            .find_masternode_list(
                                llmq_block_hash,
                                &cache.mn_lists,
                                &mut cache.needed_masternode_lists,
                            )
                        {
                            self.validate_quorum(
                                quorum,
                                has_valid_quorums,
                                llmq_block_hash,
                                masternodes,
                                cache,
                            )
                        }
                    });
            }
        });
        let mut quorums = base_quorums.clone();
        quorums.extend(
            added
                .clone()
                .into_iter()
                .filter(|(key, _entries)| !quorums.contains_key(key))
                .collect::<BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>>>(),
        );
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
        (added, quorums, has_valid_quorums)
    }

    pub fn validate_quorum(
        &self,
        quorum: &mut masternode::LLMQEntry,
        has_valid_quorums: bool,
        block_hash: UInt256,
        masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        cache: &mut MasternodeProcessorCache,
    ) {
        let block_height = self.lookup_block_height_by_hash(block_hash);
        let valid_masternodes = if quorum.index.is_some() {
            self.get_rotated_masternodes_for_quorum(
                quorum.llmq_type,
                block_hash,
                block_height,
                &mut cache.llmq_members,
                &mut cache.llmq_indexed_members,
                &cache.mn_lists,
                &cache.llmq_snapshots,
                &mut cache.needed_masternode_lists
            )
        } else {
            Self::get_masternodes_for_quorum(
                quorum.llmq_type,
                masternodes,
                quorum.llmq_quorum_hash(),
                block_height)
        };
        self.validate_signature(valid_masternodes, quorum, block_height, has_valid_quorums);
    }

    pub fn get_masternodes_for_quorum(llmq_type: LLMQType, masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>, quorum_modifier: UInt256, block_height: u32) -> Vec<masternode::MasternodeEntry> {
        let quorum_count = llmq_type.size();
        let masternodes_in_list_count = masternodes.len();
        let mut score_dictionary = Self::score_masternodes_map(masternodes, quorum_modifier, block_height);
        let mut scores: Vec<UInt256> = score_dictionary.clone().into_keys().collect();
        scores.sort_by(|&s1, &s2| s2.clone().reversed().cmp(&s1.clone().reversed()));
        let mut valid_masternodes: Vec<masternode::MasternodeEntry> = Vec::new();
        let count = min(masternodes_in_list_count, scores.len());
        for i in 0..count {
            if let Some(masternode) = score_dictionary.get_mut(&scores[i]) {
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

    pub fn score_masternodes_map(
        masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        quorum_modifier: UInt256,
        block_height: u32,
    ) -> BTreeMap<UInt256, masternode::MasternodeEntry> {
        masternodes
            .clone()
            .into_iter()
            .filter_map(|(_, entry)| {
                match masternode::MasternodeList::masternode_score(&entry, quorum_modifier, block_height) {
                    Some(score) => Some((score, entry)),
                    None => None
                }
            })
            .collect()
    }

    fn sort_scored_masternodes(scored_masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>) -> Vec<masternode::MasternodeEntry> {
        let mut v = Vec::from_iter(scored_masternodes);
        v.sort_by(|(s1, _), (s2, _b)| s2.clone().reversed().cmp(&s1.clone().reversed()));
        v.into_iter().map(|(s, node)| node).collect()
    }

    pub fn valid_masternodes_for_rotated_quorum_map(
        masternodes: Vec<masternode::MasternodeEntry>,
        quorum_modifier: UInt256,
        quorum_count: u32,
        block_height: u32,
    ) -> Vec<masternode::MasternodeEntry> {
        let scored_masternodes = masternodes
            .into_iter()
            .fold(BTreeMap::new(), |mut map, entry| {
                match masternode::MasternodeList::masternode_score(&entry, quorum_modifier, block_height) {
                    Some(score) => {
                        map.insert(score, entry);
                    }
                    None => {}
                };
                map
            });
        Self::sort_scored_masternodes(scored_masternodes)
    }

    pub fn valid_masternodes_for_rotated_quorum(
        masternodes: BTreeMap<UInt256, masternode::MasternodeEntry>,
        quorum_modifier: UInt256,
        quorum_count: u32,
        block_height: u32,
    ) -> Vec<masternode::MasternodeEntry> {
        let scored_masternodes = Self::score_masternodes_map(masternodes, quorum_modifier, block_height);
        let scored_sorted_masternodes = Self::sort_scored_masternodes(scored_masternodes);
        scored_sorted_masternodes
    }

    // Same as in LLMQEntry
    // TODO: migrate to LLMQEntry
    fn build_llmq_modifier(llmq_type: LLMQType, block_hash: UInt256) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(33);
        let offset: &mut usize = &mut 0;
        *offset += encode::VarInt(llmq_type as u64)
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += block_hash.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    // Reconstruct quorum members at index from snapshot
    pub fn quorum_quarter_members_by_snapshot(
        &self,
        llmq_params: LLMQParams,
        quorum_base_block_height: u32,
        cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>,
        unknown_lists: &mut Vec<UInt256>,
    ) -> Vec<Vec<masternode::MasternodeEntry>> {
        let work_block_height = quorum_base_block_height - 8;
        let llmq_type = llmq_params.r#type;
        let quorum_count = llmq_params.signing_active_quorum_count;
        let quorum_size = llmq_params.size;
        let quarter_size = (quorum_size / 4) as usize;
        // Quorum members dichotomy in snapshot
        match self.lookup_block_hash_by_height(work_block_height) {
            None => panic!("missing block for height: {}", work_block_height),
            Some(work_block_hash) => {
                //println!("quorum_quarter_members_by_snapshot: find masternode list for: {}: {} (cached_snapshots: {:#?})", work_block_height, work_block_hash.clone().reversed(), cached_snapshots);
                if let Some(masternode_list) =
                    self.find_masternode_list(work_block_hash, &cached_lists, unknown_lists)
                {
                    if let Some(snapshot) = self.find_snapshot(work_block_hash, &cached_snapshots) {
                        let mut i: u32 = 0;
                        // TODO: partition with enumeration doesn't work here, so need to change
                        // nodes.into_iter().enumerate().partition(|&(i, _)| snapshot.member_list.bit_is_true_at_le_index(i as u32))
                        let quorum_modifier = Self::build_llmq_modifier(llmq_type, work_block_hash);
                        let scored_masternodes = Self::score_masternodes_map(masternode_list.masternodes, quorum_modifier, work_block_height);
                        let scored_sorted_masternodes = Self::sort_scored_masternodes(scored_masternodes);
                        let (used_at_h, unused_at_h) = scored_sorted_masternodes
                        .into_iter()
                        .partition(|_| {
                            let is_true =
                                snapshot.member_list.as_slice().bit_is_true_at_le_index(i);
                            i += 1;
                            is_true
                        });
                        let sorted_used_at_h = Self::valid_masternodes_for_rotated_quorum_map(
                            used_at_h,
                            quorum_modifier,
                            quorum_count,
                            work_block_height,
                        );
                        let sorted_unused_at_h = Self::valid_masternodes_for_rotated_quorum_map(
                            unused_at_h,
                            quorum_modifier,
                            quorum_count,
                            work_block_height,
                        );
                        // println!("used_at_h: {:#?}", sorted_used_at_h.iter().map(|m|m.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        // println!("unused_at_h: {:#?}", sorted_unused_at_h.iter().map(|m|m.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        let mut sorted_combined_mns_list = sorted_unused_at_h;
                        sorted_combined_mns_list.extend(sorted_used_at_h);
                        // println!("sorted_combined_mns_list: {:#?}", sorted_combined_mns_list.iter().map(|m|m.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        snapshot.apply_skip_strategy(
                            sorted_combined_mns_list,
                            quorum_count as usize,
                            quarter_size,
                        )
                    } else {
                        self.log(format!(
                            "missing snapshot for block at height: {}: {}",
                            work_block_height, work_block_hash
                        ));
                        vec![]
                    }
                } else {
                    self.log(format!(
                        "missing masternode_list for block at height: {}: {}",
                        work_block_height, work_block_hash.clone().reversed()
                    ));
                    vec![]
                }
            }
        }
    }

    // Determine quorum members at new index
    pub fn new_quorum_quarter_members(
        &self,
        params: LLMQParams,
        quorum_base_block_height: u32,
        previous_quarters: [Vec<Vec<masternode::MasternodeEntry>>; 3],
        cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        unknown_lists: &mut Vec<UInt256>,
    ) -> Vec<Vec<masternode::MasternodeEntry>> {
        let quorum_count = params.signing_active_quorum_count;
        let num_quorums = quorum_count as usize;
        let mut quarter_quorum_members =
            Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let quorum_size = params.size as usize;
        let quarter_size = quorum_size / 4;
        let work_block_height = quorum_base_block_height - 8;
        match self.lookup_block_hash_by_height(work_block_height) {
            None => panic!("missing block for height: {}", work_block_height),
            Some(work_block_hash) => {
                if let Some(masternode_list) =
                    self.find_masternode_list(work_block_hash, cached_lists, unknown_lists)
                {
                    if masternode_list.masternodes.len() < quarter_size {
                        self.log(format!("masternode list at {}: {} has less masternodes ({}) then required for quarter size: ({})", work_block_height, work_block_hash, masternode_list.masternodes.len(), quarter_size));
                        quarter_quorum_members
                    } else {
                        let mut masternodes_used_at_h = Vec::<masternode::MasternodeEntry>::new();
                        let mut masternodes_unused_at_h = Vec::<masternode::MasternodeEntry>::new();
                        let mut masternodes_used_at_h_index =
                            Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
                        for i in 0..num_quorums {
                            masternodes_used_at_h_index.insert(i, vec![]);
                        }
                        (0..num_quorums).into_iter().for_each(|i| {
                            // for quarters h - c, h -2c, h -3c
                            previous_quarters.iter().for_each(|q| {
                                if let Some(quarter) = q.get(i) {
                                    quarter.iter().for_each(|node| {
                                        if node.is_valid {
                                            masternodes_used_at_h.push(node.clone());
                                            masternodes_used_at_h_index[i].push(node.clone());
                                        }
                                    });
                                }
                            });
                        });
                        masternode_list.masternodes.into_values().for_each(|mn| {
                            if mn.is_valid
                                && masternodes_used_at_h
                                    .iter()
                                    .filter(|node|
                                        mn.provider_registration_transaction_hash
                                            == node.provider_registration_transaction_hash
                                    )
                                    .count()
                                    == 0
                            {
                                masternodes_unused_at_h.push(mn);
                            }
                        });
                        let modifier = Self::build_llmq_modifier(params.r#type, work_block_hash);
                        let sorted_used_mns_list = Self::valid_masternodes_for_rotated_quorum_map(
                            masternodes_used_at_h,
                            modifier,
                            quorum_count,
                            work_block_height,
                        );
                        let sorted_unused_mns_list = Self::valid_masternodes_for_rotated_quorum_map(
                            masternodes_unused_at_h,
                            modifier,
                            quorum_count,
                            work_block_height,
                        );
                        // println!("----------- buildNewQuorumQuarterMembers --------- ");
                        // println!("sortedMnsUsedAtH: {:#?}", sorted_used_mns_list.iter().map(|m| m.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        // println!("sortedMnsNotUsedAtH: {:#?}", sorted_unused_mns_list.iter().map(|m| m.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        let mut sorted_combined_mns_list = sorted_unused_mns_list;
                        sorted_combined_mns_list.extend(sorted_used_mns_list);
                        // println!("sortedCombinedMnsList h[{}] {:#?}", quorum_base_block_height, sorted_combined_mns_list.iter().map(|n|n.provider_registration_transaction_hash.clone().reversed().to_string().chars().take(4).collect()).collect::<Vec<String>>());
                        // println!("sortedCombinedMnsList h[{}] {:#?}", quorum_base_block_height, sorted_combined_mns_list.iter().map(|n|n.provider_registration_transaction_hash.clone().reversed()).collect::<Vec<UInt256>>());
                        let mut skip_list = Vec::<i32>::new();
                        let mut first_skipped_index = 0i32;
                        let mut idx = 0i32;
                        (0..num_quorums).for_each(|i| {
                            if quarter_quorum_members.get(i).is_none() {
                                quarter_quorum_members.insert(i, vec![]);
                            }
                            while quarter_quorum_members.get(i).unwrap().len() < quarter_size {
                                let mn = sorted_combined_mns_list.get(idx as usize).unwrap();
                                if masternodes_used_at_h_index
                                    .get(i)
                                    .unwrap()
                                    .into_iter()
                                    .filter(|&node| mn.provider_registration_transaction_hash == node.provider_registration_transaction_hash)
                                    .count()
                                    == 0
                                {
                                    quarter_quorum_members.get_mut(i).unwrap().push(mn.clone());
                                } else {
                                    let skip_index = idx - first_skipped_index;
                                    if first_skipped_index == 0 {
                                        first_skipped_index = idx;
                                    }
                                    skip_list.push(idx);
                                }
                                idx += 1;
                                if idx == sorted_combined_mns_list.len() as i32 {
                                    idx = 0;
                                }
                            }
                        });
                        quarter_quorum_members
                    }
                } else {
                    self.log(format!(
                        "missing masternode list for height: {}: {}",
                        work_block_height, work_block_hash
                    ));
                    quarter_quorum_members
                }
            }
        }
    }

    fn add_quorum_members_from_quarter(
        quorum_members: &mut Vec<Vec<masternode::MasternodeEntry>>,
        quarter: &Vec<Vec<masternode::MasternodeEntry>>,
        index: usize,
    ) {
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

    fn rotate_members(
        &self,
        cycle_quorum_base_block_height: u32,
        llmq_params: LLMQParams,
        cached_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        cached_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>,
        unknown_lists: &mut Vec<UInt256>,
    ) -> Vec<Vec<masternode::MasternodeEntry>> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let prev_q_h_m_c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - cycle_length,
            cached_lists,
            cached_snapshots,
            unknown_lists,
        );
        let prev_q_h_m_2c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - 2 * cycle_length,
            cached_lists,
            cached_snapshots,
            unknown_lists,
        );
        let prev_q_h_m_3c = self.quorum_quarter_members_by_snapshot(
            llmq_params,
            cycle_quorum_base_block_height - 3 * cycle_length,
            cached_lists,
            cached_snapshots,
            unknown_lists,
        );
        // println!("INFO: Quarter H-C {:#?}", prev_q_h_m_c.iter().flat_map(|v| v.iter().map(|m| m.provider_registration_transaction_hash.clone().reversed())).collect::<Vec<UInt256>>());
        // println!("INFO: Quarter H-2C {:#?}", prev_q_h_m_2c.iter().flat_map(|v| v.iter().map(|m| m.provider_registration_transaction_hash.clone().reversed())).collect::<Vec<UInt256>>());
        // println!("INFO: Quarter H-3C {:#?}", prev_q_h_m_3c.iter().flat_map(|v| v.iter().map(|m| m.provider_registration_transaction_hash.clone().reversed())).collect::<Vec<UInt256>>());
        let mut rotated_members =
            Vec::<Vec<masternode::MasternodeEntry>>::with_capacity(num_quorums);
        let new_quarter_members = self.new_quorum_quarter_members(
            llmq_params,
            cycle_quorum_base_block_height,
            [
                prev_q_h_m_c.clone(),
                prev_q_h_m_2c.clone(),
                prev_q_h_m_3c.clone(),
            ],
            cached_lists,
            unknown_lists,
        );
        (0..num_quorums).for_each(|i| {
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_3c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_2c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &prev_q_h_m_c, i);
            Self::add_quorum_members_from_quarter(&mut rotated_members, &new_quarter_members, i);
        });
        rotated_members
    }

    /// Determine masternodes which is responsible for signing at this quorum index
    pub fn get_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: UInt256,
        block_height: u32,
        cached_llmq_members: &mut BTreeMap<LLMQType, BTreeMap<UInt256, Vec<masternode::MasternodeEntry>>>,
        cached_llmq_indexed_members: &mut BTreeMap<LLMQType, BTreeMap<llmq::LLMQIndexedHash, Vec<masternode::MasternodeEntry>>>,
        cached_mn_lists: &BTreeMap<UInt256, masternode::MasternodeList>,
        cached_llmq_snapshots: &BTreeMap<UInt256, llmq::LLMQSnapshot>,
        cached_needed_masternode_lists: &mut Vec<UInt256>,
    ) -> Vec<masternode::MasternodeEntry> {
        let map_by_type_opt = cached_llmq_members.get_mut(&llmq_type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&block_hash) {
                return members.clone();
            }
        } else {
            cached_llmq_members.insert(llmq_type, BTreeMap::new());
        }
        let map_by_type = cached_llmq_members.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        match self.lookup_block_hash_by_height(cycle_base_height) {
            None => panic!("missing hash for block at height: {}", cycle_base_height),
            Some(cycle_base_hash) => {
                let map_by_type_indexed_opt = cached_llmq_indexed_members.get_mut(&llmq_type);
                if map_by_type_indexed_opt.is_some() {
                    if let Some(members) = map_by_type_indexed_opt
                        .as_ref()
                        .unwrap()
                        .get(&llmq::LLMQIndexedHash::new(cycle_base_hash, quorum_index))
                    {
                        map_by_type.insert(block_hash, members.clone());
                        return members.clone();
                    }
                } else {
                    cached_llmq_indexed_members
                        .insert(llmq_type, BTreeMap::new());
                }
                let rotated_members = self.rotate_members(
                    cycle_base_height,
                    llmq_params,
                    cached_mn_lists,
                    cached_llmq_snapshots,
                    cached_needed_masternode_lists,
                );
                let map_indexed_quorum_members_of_type =
                    cached_llmq_indexed_members.get_mut(&llmq_type).unwrap();
                rotated_members.iter().enumerate().for_each(|(i, members)| {
                    map_indexed_quorum_members_of_type.insert(
                        llmq::LLMQIndexedHash::new(cycle_base_hash, i as u32),
                        members.clone(),
                    );
                });
                if let Some(members) = rotated_members.get(quorum_index as usize) {
                    map_by_type.insert(block_hash, members.clone());
                    return members.clone();
                }
                vec![]
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    /// FFI-callbacks
    ///////////////////////////////////////////////////////////////////////////////////////////

    pub fn lookup_masternode_list(
        &self,
        block_hash: UInt256,
    ) -> Option<masternode::MasternodeList> {
        // First look at the local cache
        let result = callbacks::lookup_masternode_list(
            block_hash,
            |h: UInt256| unsafe {
                (self.get_masternode_list_by_block_hash)(boxed(h.0), self.opaque_context)
            },
            |list: *mut types::MasternodeList| unsafe { (self.destroy_masternode_list)(list) },
        );
        result
    }

    pub fn save_masternode_list(
        &self,
        block_hash: UInt256,
        masternode_list: &masternode::MasternodeList,
    ) -> bool {
        unsafe {
            (self.save_masternode_list)(
                boxed(block_hash.0),
                boxed(masternode_list.encode()),
                self.opaque_context,
            )
        }
    }

    pub fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<UInt256> {
        callbacks::lookup_block_hash_by_height(
            block_height,
            |h: u32| unsafe { (self.get_block_hash_by_height)(h, self.opaque_context) },
            |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
        )
    }

    pub fn lookup_block_height_by_hash(&self, block_hash: UInt256) -> u32 {
        unsafe { (self.get_block_height_by_hash)(boxed(block_hash.0), self.opaque_context) }
    }

    pub fn lookup_snapshot_by_block_hash(&self, block_hash: UInt256) -> Option<llmq::LLMQSnapshot> {
        callbacks::lookup_snapshot_by_block_hash(
            block_hash,
            |h: UInt256| unsafe {
                (self.get_llmq_snapshot_by_block_hash)(boxed(h.0), self.opaque_context)
            },
            |snapshot: *mut types::LLMQSnapshot| unsafe { (self.destroy_snapshot)(snapshot) },
        )
    }

    pub fn save_snapshot(&self, block_hash: UInt256, snapshot: llmq::LLMQSnapshot) -> bool {
        println!("save_snapshot ==> {}: {}", self.lookup_block_height_by_hash(block_hash), block_hash);
        unsafe {
            (self.save_llmq_snapshot)(
                boxed(block_hash.0),
                boxed(snapshot.encode()),
                self.opaque_context,
            )
        }
    }

    pub fn lookup_merkle_root_by_hash(&self, block_hash: UInt256) -> Option<UInt256> {
        callbacks::lookup_merkle_root_by_hash(
            block_hash,
            |h: UInt256| unsafe { (self.get_merkle_root_by_hash)(boxed(h.0), self.opaque_context) },
            |hash: *mut u8| unsafe { (self.destroy_hash)(hash) },
        )
    }

    pub fn log(&self, message: String) {
        println!("{}", message);
        // let c_string = std::ffi::CString::new(message).unwrap();
        // unsafe  { (self.log_message)(c_string.as_ptr(), self.opaque_context)}
    }

    pub fn should_process_quorum(&self, llmq_type: LLMQType) -> bool {
        let should =
            unsafe { (self.should_process_llmq_of_type)(llmq_type.into(), self.opaque_context) };
        should
    }

    pub fn should_process_diff_with_range(
        &self,
        base_block_hash: UInt256,
        block_hash: UInt256,
    ) -> u8 {
        unsafe {
            (self.should_process_diff_with_range)(
                boxed(base_block_hash.0),
                boxed(block_hash.0),
                self.opaque_context,
            )
        }
    }

    pub fn add_insight(&self, block_hash: UInt256) {
        unsafe { (self.add_insight)(boxed(block_hash.0), self.opaque_context) }
    }

    /// Calls c++ BLS lib via FFI
    fn validate_signature(
        &self,
        valid_masternodes: Vec<masternode::MasternodeEntry>,
        quorum: &mut masternode::LLMQEntry,
        block_height: u32,
        mut has_valid_quorums: bool,
    ) {
        if quorum.llmq_type == LLMQType::Llmqtype60_75 {
            has_valid_quorums &= true;
        } else {
            let operator_pks: Vec<*mut [u8; 48]> = (0..valid_masternodes.len())
                .into_iter()
                .filter_map(|i| {
                    match quorum
                        .signers_bitset
                        .as_slice()
                        .bit_is_true_at_le_index(i as u32)
                    {
                        true => Some(boxed(
                            valid_masternodes[i].operator_public_key_at(block_height).0,
                        )),
                        false => None,
                    }
                })
                .collect();
            println!(
                "validate_signature: {:?} {:?} {:?}",
                valid_masternodes, quorum, operator_pks
            );
            let operator_public_keys_count = operator_pks.len();
            let is_valid_signature = unsafe {
                (self.validate_llmq)(
                    boxed(types::LLMQValidationData {
                        items: boxed_vec(operator_pks),
                        count: operator_public_keys_count,
                        commitment_hash: boxed(quorum.generate_commitment_hash().0),
                        all_commitment_aggregated_signature: boxed(
                            quorum.all_commitment_aggregated_signature.0,
                        ),
                        threshold_signature: boxed(quorum.threshold_signature.0),
                        public_key: boxed(quorum.public_key.0),
                    }),
                    self.opaque_context,
                )
            };
            let is_valid_payload = quorum.validate_payload();
            has_valid_quorums &= is_valid_payload && is_valid_signature;
        }

        if has_valid_quorums {
            quorum.verified = true;
        }
    }

    pub fn read_list_diff_from_message<'a>(
        &self,
        message: &'a [u8],
        offset: &mut usize,
    ) -> Option<llmq::MNListDiff> {
        llmq::MNListDiff::new(message, offset, |hash| {
            self.lookup_block_height_by_hash(hash)
        })
    }
}
