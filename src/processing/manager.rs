use std::cmp::min;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use hashes::{Hash, sha256};
use crate::{AddInsightBlockingLookup, BlockData, BlockHeightLookup, boxed, boxed_vec, Data, Encodable, ffi, FromFFI, inplace_intersection, LLMQType, MasternodeEntry, MasternodeList, MasternodeListDestroy, MasternodeListLookup, LLMQEntry, Reversable, ShouldProcessLLMQTypeCallback, UInt256, ValidateLLMQCallback, Zeroable};

pub fn lookup_masternode_list<'a>(
    block_hash: UInt256,
    masternode_list_lookup: MasternodeListLookup,
    masternode_list_destroy: MasternodeListDestroy,
    context: *const c_void,
) -> Option<MasternodeList<'a>> {
    let lookup_result = unsafe { masternode_list_lookup(boxed(block_hash.0), context) };
    if !lookup_result.is_null() {
        let list = unsafe { (*lookup_result).decode() };
        unsafe { masternode_list_destroy(lookup_result); }
        Some(list)
    } else {
        None
    }
}

pub fn lookup_masternodes_and_quorums_for<'a>(
    block_hash: UInt256,
    masternode_list_lookup: MasternodeListLookup,
    masternode_list_destroy: MasternodeListDestroy,
    context: *const c_void,
) -> (BTreeMap<UInt256, MasternodeEntry>, HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>) {
    let list = lookup_masternode_list(block_hash, masternode_list_lookup, masternode_list_destroy, context);
    if list.is_some() {
        let list = list.unwrap();
        (list.masternodes, list.quorums)
    } else {
        (BTreeMap::new(), HashMap::new())
    }
}

pub fn classify_masternodes(base_masternodes: BTreeMap<UInt256, MasternodeEntry>,
                        added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry>,
                        deleted_masternode_hashes: Vec<UInt256>,
                        block_height: u32,
                        block_hash: UInt256)
                        -> (BTreeMap<UInt256, MasternodeEntry>,
                            BTreeMap<UInt256, MasternodeEntry>,
                            BTreeMap<UInt256, MasternodeEntry>) {
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
    let mut modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = modified_masternode_keys
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
                    (*modified).update_with_previous_entry(old, BlockData { height: block_height, hash: block_hash });
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

pub fn classify_quorums<'a>(base_quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
                            added_quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
                            deleted_quorums: HashMap<LLMQType, Vec<UInt256>>,
                            masternode_list_lookup: MasternodeListLookup,
                            masternode_list_destroy: MasternodeListDestroy,
                            use_insight_as_backup: bool,
                            add_insight_lookup: AddInsightBlockingLookup,
                            should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
                            validate_llmq_callback: ValidateLLMQCallback,
                            block_height_lookup: BlockHeightLookup,
                            context: *const c_void)
                            -> (HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
                                HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
                                bool,
                                Vec<*mut [u8; 32]>
                        ) {
    let bh_lookup = |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) };
    let has_valid_quorums = true;
    let mut needed_masternode_lists: Vec<*mut [u8; 32]> = Vec::new();
    added_quorums.iter()
        .filter(|(&llmq_type, _)| unsafe { should_process_llmq_of_type(llmq_type.into(), context) })
        .for_each(|(&llmq_type, llmqs_of_type)| {
            (*llmqs_of_type).iter().for_each(|(&llmq_hash, &llmq)| {
                let llmq_masternode_list = lookup_masternode_list(llmq_hash, masternode_list_lookup, masternode_list_destroy, context);
                if llmq_masternode_list.is_some() {
                    validate_quorum(llmq_type,
                                    llmq,
                                    has_valid_quorums,
                                    llmq_masternode_list.unwrap(),
                                    bh_lookup,
                                    validate_llmq_callback,
                                    context);
                } else if bh_lookup(llmq_hash) != u32::MAX {
                    needed_masternode_lists.push(boxed(llmq_hash.0));
                } else if use_insight_as_backup {
                    unsafe { add_insight_lookup(boxed(llmq_hash.0), context) };
                    if bh_lookup(llmq_hash) != u32::MAX {
                        needed_masternode_lists.push(boxed(llmq_hash.0));
                    }
                }
            });
        });
    let mut quorums = base_quorums.clone();
    quorums.extend(added_quorums
        .clone()
        .into_iter()
        .filter(|(key, _entries)| !quorums.contains_key(key))
        .collect::<HashMap<LLMQType, HashMap<UInt256, LLMQEntry>>>());
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

pub fn validate_quorum<F: Fn(UInt256) -> u32>(
    llmq_type: LLMQType,
    mut quorum: LLMQEntry,
    mut has_valid_quorums: bool,
    llmq_masternode_list: MasternodeList,
    block_height_lookup: F,
    validate_llmq_callback: ValidateLLMQCallback,
    context: *const c_void,
) {
    let block_height: u32 = block_height_lookup(llmq_masternode_list.block_hash);
    let valid_masternodes = valid_masternodes_for(llmq_masternode_list.masternodes, quorum.llmq_quorum_hash(), llmq_type.size(), block_height);
    let operator_pks: Vec<*mut [u8; 48]> = (0..valid_masternodes.len())
        .into_iter()
        .filter(|&i| quorum.signers_bitset.bit_is_true_at_le_index(i as u32))
        .map(|i| boxed(valid_masternodes[i].operator_public_key_at(block_height).0))
        .collect();
    let operator_public_keys_count = operator_pks.len();
    let is_valid_signature = unsafe {
        validate_llmq_callback(
            boxed(ffi::types::LLMQValidationData {
                items: boxed_vec(operator_pks),
                count: operator_public_keys_count,
                commitment_hash: boxed(quorum.generate_commitment_hash().0),
                all_commitment_aggregated_signature: boxed(quorum.all_commitment_aggregated_signature.0),
                threshold_signature: boxed(quorum.threshold_signature.0),
                public_key: boxed(quorum.public_key.0)
            }),
            context
        )
    };
    has_valid_quorums &= quorum.validate_payload() && is_valid_signature;
    if has_valid_quorums {
        quorum.verified = true;
    }
}

pub fn masternode_score(entry: MasternodeEntry, modifier: UInt256, block_height: u32) -> Option<UInt256> {
    if entry.confirmed_hash_at(block_height).is_none() {
        return None;
    }
    let mut buffer: Vec<u8> = Vec::new();
    if let Some(hash) = entry.confirmed_hash_hashed_with_provider_registration_transaction_hash_at(block_height) {
        hash.consensus_encode(&mut buffer).unwrap();
    }
    modifier.consensus_encode(&mut buffer).unwrap();
    Some(UInt256(sha256::Hash::hash(&buffer).into_inner()))
}

pub fn valid_masternodes_for(masternodes: BTreeMap<UInt256, MasternodeEntry>, quorum_modifier: UInt256, quorum_count: u32, block_height: u32) -> Vec<MasternodeEntry> {
    let mut score_dictionary: BTreeMap<UInt256, MasternodeEntry> = masternodes.clone().into_iter().filter_map(|(_, entry)| {
        let score = masternode_score(entry.clone(), quorum_modifier, block_height);
        if score.is_some() && !score.unwrap().0.is_empty() {
            Some((score.unwrap(), entry))
        } else {
            None
        }
    }).collect();
    let mut scores: Vec<UInt256> = score_dictionary.clone().into_keys().collect();
    scores.sort_by(|&s1, &s2| s2.clone().reversed().cmp(&s1.clone().reversed()));
    let mut masternodes: Vec<MasternodeEntry> = Vec::new();
    let masternodes_in_list_count = masternodes.len();
    let count = min(masternodes_in_list_count, scores.len());
    for i in 0..count {
        if let Some(masternode) = score_dictionary.get_mut(&scores[i]) {
            if (*masternode).is_valid_at(block_height) {
                masternodes.push((*masternode).clone());
            }
        }
        if masternodes.len() == quorum_count as usize {
            break;
        }
    }
    masternodes
}
