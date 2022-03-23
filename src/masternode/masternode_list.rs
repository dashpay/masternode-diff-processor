use std::cmp::min;
use std::collections::{BTreeMap, HashMap};
use crate::{CoinbaseTransaction, LLMQType};
use crate::crypto::byte_util::{merkle_root_from_hashes, Reversable, UInt256};
use crate::masternode::llmq_entry::LLMQEntry;
use crate::masternode::masternode_entry::MasternodeEntry;
use crate::processing::masternode_score;
use crate::Zeroable;

#[derive(Clone)]
pub struct MasternodeList<'a> {
    pub block_hash: UInt256,
    pub known_height: u32,
    pub masternode_merkle_root: Option<UInt256>,
    pub llmq_merkle_root: Option<UInt256>,
    pub masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
}

impl<'a> std::fmt::Debug for MasternodeList<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeList")
            .field("block_hash", &self.block_hash)
            .field("known_height", &self.known_height)
            .field("masternode_merkle_root", &self.masternode_merkle_root)
            .field("llmq_merkle_root", &self.llmq_merkle_root)
            .field("masternodes", &self.masternodes.len())
            .field("quorums", &self.quorums)
            .finish()
    }
}

impl<'a> MasternodeList<'a> {
    pub fn new(
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        quorums: HashMap<LLMQType, HashMap<UInt256, LLMQEntry<'a>>>,
        block_hash: UInt256,
        block_height: u32,
        quorums_active: bool
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

    pub fn valid_masternodes_for(&self, quorum_modifier: UInt256, quorum_count: u32, block_height: u32) -> Vec<MasternodeEntry> {
        let mut score_dictionary: BTreeMap<UInt256, MasternodeEntry> = self.masternodes
            .clone()
            .into_iter()
            .filter_map(|(h, entry)| match masternode_score(entry.clone(), quorum_modifier, block_height) {
                Some(score) => if score.is_zero() { None } else { Some((score, entry)) },
                None => None
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
            println!("Block height lookup queried an unknown block {:?}", self.block_hash);
            None
        } else {
            let mut pro_tx_hashes: Vec<UInt256> = self.masternodes.clone().into_keys().collect();
            pro_tx_hashes
                .sort_by(|&h1, &h2|
                    h1.clone()
                        .reversed()
                        .cmp(&h2.clone().reversed()));
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
        let mut llmq_commitment_hashes: Vec<UInt256> = self.quorums
            .clone()
            .into_values()
            .fold(Vec::new(), |mut acc, q_map| {
                let quorum_hashes: Vec<UInt256> = q_map
                    .into_values()
                    .map(|entry| entry.entry_hash)
                    .collect();
                acc.extend(quorum_hashes);
                acc
            });
        llmq_commitment_hashes.sort();
        //println!("MasternodeList.llmq_hashes: {:?}", llmq_commitment_hashes);
        llmq_commitment_hashes
    }

    pub fn masternode_for(&self, registration_hash: UInt256) -> Option<&MasternodeEntry> {
        self.masternodes.get(&registration_hash)
    }

    pub fn has_valid_mn_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        // we need to check that the coinbase is in the transaction hashes we got back
        // and is in the merkle block
        if let Some(mn_merkle_root) = self.masternode_merkle_root {
            println!("rootMNListValid: {:?} == {:?}", mn_merkle_root, tx.merkle_root_mn_list);
            tx.merkle_root_mn_list == mn_merkle_root
        } else {
            false
        }
    }

    pub fn has_valid_llmq_list_root(&self, tx: &CoinbaseTransaction) -> bool {
        let q_merkle_root = self.llmq_merkle_root;
        let ct_q_merkle_root = tx.merkle_root_llmq_list;
        println!("LLMQ list root valid: {:?} == {:?}", q_merkle_root, ct_q_merkle_root);
        let has_valid_quorum_list_root =
            q_merkle_root.is_some() &&
                ct_q_merkle_root.is_some() &&
                ct_q_merkle_root.unwrap() == q_merkle_root.unwrap();
        if !has_valid_quorum_list_root {
            println!("LLMQ Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
                     tx.height,
                     tx.base.version,
                     tx.merkle_root_llmq_list,
                     self.llmq_merkle_root);
        }
        has_valid_quorum_list_root
    }
}
