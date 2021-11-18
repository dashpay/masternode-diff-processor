use std::cmp::min;
use std::collections::{BTreeMap, HashMap};
use crate::common::llmq_type::LLMQType;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{merkle_root_from_hashes, Reversable, UInt256};
use crate::hashes::{Hash, sha256};
use crate::masternode::quorum_entry::QuorumEntry;
use crate::masternode::masternode_entry::MasternodeEntry;

#[repr(C)]
#[derive(Clone)]
pub struct MasternodeList<'a> {
    pub block_hash: UInt256,
    pub known_height: u32,
    pub masternode_merkle_root: Option<UInt256>,
    pub quorum_merkle_root: Option<UInt256>,
    pub masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub quorums: HashMap<LLMQType, HashMap<UInt256, QuorumEntry<'a>>>,
}

impl<'a> MasternodeList<'a> {
    pub fn new(
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        quorums: HashMap<LLMQType, HashMap<UInt256, QuorumEntry<'a>>>,
        block_hash: UInt256,
        block_height: u32
    ) -> Self {
        let mut list = Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: None,
            quorum_merkle_root: None,
            masternodes,
        };
        if let Some(hashes) = list.hashes_for_merkle_root(block_height) {
            list.masternode_merkle_root = merkle_root_from_hashes(hashes);
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
        let score_dictionary = self.score_dictionary_for_quorum_modifier(quorum_modifier, block_height);
        // into_keys perform sorting like below
        /*NSArray *scores = [[score_dictionary allKeys] sortedArrayUsingComparator:^NSComparisonResult(id _Nonnull obj1, id _Nonnull obj2) {
            UInt256 hash1 = *(UInt256 *)((NSData *)obj1).bytes;
            UInt256 hash2 = *(UInt256 *)((NSData *)obj2).bytes;
            return uint256_sup(hash1, hash2) ? NSOrderedAscending : NSOrderedDescending;
        }];*/
        let scores: Vec<UInt256> = score_dictionary.clone().into_keys().collect();
        let mut masternodes: Vec<MasternodeEntry> = Vec::new();
        let masternodes_in_list_count = self.masternodes.len();
        let count = min(masternodes_in_list_count, scores.len());
        for i in 0..count {
            let score = scores.get(i).unwrap();
            let masternode = &score_dictionary[score];
            if masternode.is_valid_at(block_height) {
                masternodes.push(masternode.clone());
            }
            if masternodes.len() == quorum_count as usize {
                break;
            }
        }
        masternodes
    }

    pub fn score_dictionary_for_quorum_modifier(&self, quorum_modifier: UInt256, block_height: u32) -> BTreeMap<UInt256, MasternodeEntry> {
        self.masternodes.clone().into_iter().filter_map(|(_, entry)| {
            let score = self.masternode_score(entry.clone(), quorum_modifier, block_height);
            if score.is_some() && !score.unwrap().0.is_empty() {
                Some((score.unwrap(), entry))
            } else {
                None
            }
        }).collect()

    }

    pub fn masternode_score(&self, masternode_entry: MasternodeEntry, modifier: UInt256, block_height: u32) -> Option<UInt256> {
        if masternode_entry.confirmed_hash_at(block_height).is_none() {
            return None;
        }
        let mut buffer: Vec<u8> = Vec::new();
        if let Some(hash) = masternode_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash_at(block_height) {
            hash.consensus_encode(&mut buffer).unwrap();
        }
        modifier.consensus_encode(&mut buffer).unwrap();
        Some(UInt256(sha256::Hash::hash(&buffer).into_inner()))
    }

    pub fn provider_tx_ordered_hashes(&self) -> Vec<UInt256> {
        let mut pro_tx_hashes: Vec<UInt256> = self.masternodes.clone().into_keys().map(|mut h|h.reversed()).collect();
        pro_tx_hashes.sort();
        pro_tx_hashes
    }

    pub fn hashes_for_merkle_root(&self, block_height: u32) -> Option<Vec<UInt256>> {
        let pro_tx_hashes: Vec<UInt256> = self.provider_tx_ordered_hashes();
        if block_height == u32::MAX {
            println!("Block height lookup queried an unknown block {:?}", self.block_hash);
            None
        } else {
            let mns = self.masternodes.clone();
            Some(pro_tx_hashes
                .clone()
                .into_iter()
                .map(|mut hash| {
                    let h = hash.reversed();
                    let mn = &mns[&h];
                    mn.simplified_masternode_entry_hash_at(block_height)
                })
                .collect())
        }
    }

    pub fn quorum_merkle_root(&mut self) -> Option<UInt256> {
        if self.quorum_merkle_root.is_none() {
            let mut llmq_commitment_hashes = Vec::new();
            let quorums = self.quorums.clone().into_values();
            for quorums_of_type in quorums {
                for QuorumEntry { quorum_entry_hash, .. } in quorums_of_type.into_values() {
                    llmq_commitment_hashes.push(quorum_entry_hash);
                }
            }
            llmq_commitment_hashes.sort();
            self.quorum_merkle_root = merkle_root_from_hashes(llmq_commitment_hashes);
        }
        self.quorum_merkle_root
    }

}
