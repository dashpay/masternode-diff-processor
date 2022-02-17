use std::cmp::min;
use std::collections::{BTreeMap, HashMap, HashSet};
use hashes::{Hash, sha256};
use crate::{BlockData, boxed, boxed_vec, Data, Encodable, ffi, FromFFI, inplace_intersection, MasternodeEntry, MasternodeList, LLMQEntry, Reversable, UInt256, Zeroable, LLMQType};
use crate::ffi::types::LLMQValidationData;

#[derive(Clone, Copy, Debug)]
pub struct Manager<
    BHL: Fn(UInt256) -> u32 + Copy,
    MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
    MND: Fn(*const ffi::types::MasternodeList) + Copy,
    AIL: Fn(UInt256) + Copy,
    SPL: Fn(LLMQType) -> bool + Copy,
    VQL: Fn(LLMQValidationData) -> bool + Copy,
> {
    pub block_height_lookup: BHL,
    pub masternode_list_lookup: MNL,
    pub masternode_list_destroy: MND,
    pub add_insight_lookup: AIL,
    pub should_process_llmq_of_type: SPL,
    pub validate_llmq_callback: VQL,
    pub use_insight_as_backup: bool,
    pub base_masternode_list_hash: Option<UInt256>,
}

pub fn lookup_masternode_list<'a,
    MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
    MND: Fn(*const ffi::types::MasternodeList) + Copy,
>(
    block_hash: UInt256,
    masternode_list_lookup: MNL,
    masternode_list_destroy: MND,
) -> Option<MasternodeList<'a>> {
    //println!("lookup_masternode_list <-: {:?}", hex_with_data(block_hash.0.as_slice()));
    let lookup_result = masternode_list_lookup(block_hash);
    if !lookup_result.is_null() {
        let list_encoded = unsafe { *lookup_result };
        println!("lookup_masternode_list (encoded) ->: {:?}", list_encoded.llmq_type_maps);
        let list = unsafe { list_encoded.decode() };
        println!("lookup_masternode_list (decoded) ->: {:?}", list);
        masternode_list_destroy(lookup_result);
        println!("lookup_masternode_list (after destroy) ->: {:?}", list);
        Some(list)
    } else {
        None
    }
}

pub fn lookup_masternodes_and_quorums_for<'a,
    MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
    MND: Fn(*const ffi::types::MasternodeList) + Copy,
>(
    block_hash: Option<UInt256>,
    masternode_list_lookup: MNL,
    masternode_list_destroy: MND,
) -> (BTreeMap<UInt256, MasternodeEntry>, HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>) {
    if let Some(block_hash) = block_hash {
        if let Some(list) = lookup_masternode_list(block_hash, masternode_list_lookup, masternode_list_destroy) {
            return (list.masternodes, list.quorums);
        }
    }
    (BTreeMap::new(), HashMap::new())
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

pub fn classify_quorums<'a,
    MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
    MND: Fn(*const ffi::types::MasternodeList) + Copy,
    AIL: Fn(UInt256) + Copy,
    SPL: Fn(LLMQType) -> bool + Copy,
    BHL: Fn(UInt256) -> u32 + Copy,
    VQL: Fn(LLMQValidationData) -> bool + Copy,
>(
    base_quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
    added_quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
    deleted_quorums: HashMap<LLMQType, Vec<UInt256>>,
    manager: Manager<BHL, MNL, MND, AIL, SPL, VQL>,
)
    -> (HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
        HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
        bool,
        Vec<*mut [u8; 32]>
    ) {
    //#[cfg(test)] log_quorums_map(base_quorums.clone(), "old_quorums".to_string());
    //#[cfg(test)] log_quorums_map(added_quorums.clone(), "added_quorums".to_string());
    let has_valid_quorums = true;
    let mut needed_masternode_lists: Vec<*mut [u8; 32]> = Vec::new();
    added_quorums.iter()
        .for_each(|(&llmq_type, llmqs_of_type)| {
            if (manager.should_process_llmq_of_type)(llmq_type) {
                (*llmqs_of_type).iter().for_each(|(&llmq_hash, &quorum)| {
                    match lookup_masternode_list(llmq_hash, manager.masternode_list_lookup, manager.masternode_list_destroy) {
                        Some(llmq_masternode_list) =>
                            validate_quorum(
                                quorum,
                                has_valid_quorums,
                                llmq_masternode_list,
                                manager.block_height_lookup,
                                manager.validate_llmq_callback),
                        None =>
                            if (manager.block_height_lookup)(llmq_hash) != u32::MAX {
                                needed_masternode_lists.push(boxed(llmq_hash.0));
                            } else if manager.use_insight_as_backup {
                                (manager.add_insight_lookup)(llmq_hash);
                                if (manager.block_height_lookup)(llmq_hash) != u32::MAX {
                                    needed_masternode_lists.push(boxed(llmq_hash.0));
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
        .collect::<HashMap<LLMQType, HashMap<UInt256, LLMQEntry>>>());
    //#[cfg(test)] log_quorums_map(quorums.clone(), "quorums_after_add".to_string());
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

    //#[cfg(test)] log_quorums_map(quorums.clone(), "quorums".to_string());
    (added_quorums, quorums, has_valid_quorums, needed_masternode_lists)
}


#[cfg(test)]
fn log_quorums_map(q: HashMap<LLMQType, HashMap<UInt256, LLMQEntry>>, id: String) {
    println!("{} hashes: [", id);
    let mut bmap: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = BTreeMap::new();
    for (qtype, map) in q.clone() {
        let qqtype: u8 = qtype.into();
        let mut bhmap: BTreeMap<UInt256, LLMQEntry> = BTreeMap::new();
        for (hash, entry) in map {
            bhmap.insert(hash, entry);
        }
        bmap.insert(qtype, bhmap);
    }
    for (qtype, map) in bmap {
        let qqtype: u8 = qtype.into();
        for (hash, entry) in map {
            println!("{}:{}", qqtype, hash);
        }
    }
    println!("]");
}

pub fn validate_quorum<
    BHL: Fn(UInt256) -> u32,
    VQL: Fn(LLMQValidationData) -> bool + Copy,
>(
    mut quorum: LLMQEntry,
    mut has_valid_quorums: bool,
    llmq_masternode_list: MasternodeList,
    block_height_lookup: BHL,
    validate_llmq_callback: VQL
) {
    let block_height: u32 = block_height_lookup(llmq_masternode_list.block_hash);
    let quorum_modifier = quorum.llmq_quorum_hash();
    let quorum_count = quorum.llmq_type.size();
    let valid_masternodes = valid_masternodes_for(llmq_masternode_list.masternodes, quorum_modifier, quorum_count, block_height);
    let operator_pks: Vec<*mut [u8; 48]> = (0..valid_masternodes.len())
        .into_iter()
        .filter_map(|i| match quorum.signers_bitset.bit_is_true_at_le_index(i as u32) {
            true => Some(boxed(valid_masternodes[i].operator_public_key_at(block_height).0)),
            false => None
        })
        .collect();
    let operator_public_keys_count = operator_pks.len();
    let is_valid_signature = validate_llmq_callback(ffi::types::LLMQValidationData {
        items: boxed_vec(operator_pks),
        count: operator_public_keys_count,
        commitment_hash: boxed(quorum.generate_commitment_hash().0),
        all_commitment_aggregated_signature: boxed(quorum.all_commitment_aggregated_signature.0),
        threshold_signature: boxed(quorum.threshold_signature.0),
        public_key: boxed(quorum.public_key.0)
    });
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
    let masternodes_in_list_count = masternodes.len();
    let mut valid_masternodes: Vec<MasternodeEntry> = Vec::new();
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
