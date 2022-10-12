use crate::common::LLMQType;
use crate::masternode::{LLMQEntry, MasternodeEntry};
use crate::tx::CoinbaseTransaction;
use dash_spv_primitives::consensus::Encodable;
use dash_spv_primitives::crypto::byte_util::{merkle_root_from_hashes, Reversable, Zeroable};
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::{sha256, Hash};
use std::cmp::min;
use std::collections::BTreeMap;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct MasternodeList {
    pub block_hash: UInt256,
    pub known_height: u32,
    pub masternode_merkle_root: Option<UInt256>,
    pub llmq_merkle_root: Option<UInt256>,
    pub masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
}

impl Default for MasternodeList {
    fn default() -> Self {
        Self {
            block_hash: UInt256::MAX,
            known_height: 0,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes: Default::default(),
            quorums: Default::default(),
        }
    }
}

impl<'a> std::fmt::Debug for MasternodeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeList")
            .field("block_hash", &self.block_hash)
            .field("known_height", &self.known_height)
            .field("masternode_merkle_root", &self.masternode_merkle_root)
            .field("llmq_merkle_root", &self.llmq_merkle_root)
            .field("masternodes", &self.masternodes.len())
            .field("quorums", &self.quorums.len())
            .finish()
    }
}

impl MasternodeList {
    pub fn new(
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
        block_hash: UInt256,
        block_height: u32,
        quorums_active: bool,
    ) -> Self {
        let mut list = Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes,
        };
        if let Some(hashes) = list.hashes_for_merkle_root(block_height) {
            list.masternode_merkle_root = merkle_root_from_hashes(hashes);
        }
        if quorums_active {
            let hashes = list.hashes_for_quorum_merkle_root();
            list.llmq_merkle_root = merkle_root_from_hashes(hashes);
        }
        list
    }

    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len() as u64;
        }
        count
    }

    pub fn valid_masternodes_for(
        &self,
        quorum_modifier: UInt256,
        quorum_count: u32,
        block_height: u32,
    ) -> Vec<MasternodeEntry> {
        let mut score_dictionary: BTreeMap<UInt256, MasternodeEntry> = self
            .masternodes
            .clone()
            .into_iter()
            .filter_map(|(_h, entry)| {
                match Self::masternode_score(entry.clone(), quorum_modifier, block_height) {
                    Some(score) => {
                        if score.is_zero() {
                            None
                        } else {
                            Some((score, entry))
                        }
                    }
                    None => None,
                }
            })
            .collect();
        let mut scores: Vec<UInt256> = score_dictionary.clone().into_keys().collect();
        scores.sort_by(|&s1, &s2| s2.clone().reversed().cmp(&s1.clone().reversed()));
        let mut masternodes: Vec<MasternodeEntry> = Vec::new();
        let masternodes_in_list_count = self.masternodes.len();
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

    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<UInt256>> {
        if block_height == u32::MAX {
            println!(
                "Block height lookup queried an unknown block {:?}",
                self.block_hash
            );
            None
        } else {
            let mut pro_tx_hashes: Vec<UInt256> = self.masternodes.clone().into_keys().collect();
            pro_tx_hashes.sort_by(|&h1, &h2| h1.clone().reversed().cmp(&h2.clone().reversed()));
            let mns = self.masternodes.clone();
            let entry_hashes = pro_tx_hashes
                .clone()
                .into_iter()
                .map(|hash| {
                    let h = hash.clone();
                    let mn = &mns[&h];
                    let entry_hash = mn.entry_hash_at(block_height);
                    entry_hash
                })
                .collect();
            Some(entry_hashes)
        }
    }

    fn hashes_for_quorum_merkle_root(&self) -> Vec<UInt256> {
        let mut llmq_commitment_hashes: Vec<UInt256> =
            self.quorums
                .clone()
                .into_values()
                .fold(Vec::new(), |mut acc, q_map| {
                    let quorum_hashes: Vec<UInt256> =
                        q_map.into_values().map(|entry| entry.entry_hash).collect();
                    acc.extend(quorum_hashes);
                    acc
                });
        llmq_commitment_hashes.sort();
        llmq_commitment_hashes
    }

    pub fn masternode_for(&self, registration_hash: UInt256) -> Option<&MasternodeEntry> {
        self.masternodes.get(&registration_hash)
    }

    pub fn has_valid_mn_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        // we need to check that the coinbase is in the transaction hashes we got back
        // and is in the merkle block
        if let Some(mn_merkle_root) = self.masternode_merkle_root {
            println!(
                "rootMNListValid: {:?} == {:?}",
                mn_merkle_root, tx.merkle_root_mn_list
            );
            tx.merkle_root_mn_list == mn_merkle_root
        } else {
            false
        }
    }

    pub fn has_valid_llmq_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        let q_merkle_root = self.llmq_merkle_root;
        let ct_q_merkle_root = tx.merkle_root_llmq_list;
        println!(
            "LLMQ list root valid: {:?} == {:?}",
            q_merkle_root, ct_q_merkle_root
        );
        let has_valid_quorum_list_root = q_merkle_root.is_some()
            && ct_q_merkle_root.is_some()
            && ct_q_merkle_root.unwrap() == q_merkle_root.unwrap();
        if !has_valid_quorum_list_root {
            println!("LLMQ Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
                     tx.height,
                     tx.base.version,
                     tx.merkle_root_llmq_list,
                     self.llmq_merkle_root);
        }
        has_valid_quorum_list_root
    }

    pub fn masternode_score(
        entry: MasternodeEntry,
        modifier: UInt256,
        block_height: u32,
    ) -> Option<UInt256> {
        if entry.confirmed_hash_at(block_height).is_none() {
            return None;
        }
        let mut buffer: Vec<u8> = Vec::new();
        if let Some(hash) =
            entry.confirmed_hash_hashed_with_provider_registration_transaction_hash_at(block_height)
        {
            hash.consensus_encode(&mut buffer).unwrap();
        }
        modifier.consensus_encode(&mut buffer).unwrap();
        Some(UInt256(sha256::Hash::hash(&buffer).into_inner()))
    }

    pub fn quorum_entry_for_platform_with_quorum_hash(
        &self,
        quorum_hash: UInt256,
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        self.quorums
            .get(&llmq_type)?
            .values()
            .find(|&entry| entry.llmq_hash == quorum_hash)
    }

    pub fn quorum_entry_for_lock_request_id(
        &self,
        request_id: UInt256,
        llmq_type: LLMQType,
    ) -> Option<&LLMQEntry> {
        let mut first_quorum: Option<&LLMQEntry> = None;
        let mut lowest_value = UInt256::MAX;
        self.quorums.get(&llmq_type)?.values().for_each(|entry| {
            let ordering_hash = entry
                .ordering_hash_for_request_id(request_id, llmq_type)
                .reversed();
            if lowest_value > ordering_hash {
                lowest_value = ordering_hash;
                first_quorum = Some(entry);
            }
        });
        first_quorum
    }
}
