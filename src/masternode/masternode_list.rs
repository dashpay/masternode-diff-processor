use std::cmp::min;
use std::collections::btree_map::Keys;
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime};
use byte::BytesExt;
use secrets::traits::Zeroable;
use serde_test::Configure;
use crate::common::llmq_type::LLMQType;
use crate::crypto::byte_util::merkle_root_from_hashes;
use crate::crypto::data_ops::sha256_1;
use crate::manager::BlockHeightLookup;
use crate::masternode::quorum_entry::QuorumEntry;
use crate::masternode::masternode_entry::MasternodeEntry;
use crate::masternode_manager::BlockHeightLookup;
use crate::simplified_masternode_entry::SimplifiedMasternodeEntry;
use crate::quorum_entry::QuorumEntry;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MasternodeList<'a> {
    pub quorums: HashMap<LLMQType, HashMap<[u8; 32], QuorumEntry>>,
    pub block_hash: [u8; 32],
    pub known_height: Option<u32>,
    pub masternode_merkle_root: [u8; 32],
    pub quorum_merkle_root: [u8; 32],
    // simplified_masternode_list_dictionary_by_reversed_registration_transaction_hash
    pub masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
}

impl MasternodeList {
    pub fn new(
        masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
        quorums: HashMap<LLMQType, HashMap<[u8; 32], QuorumEntry>>,
        block_hash: [u8; 32],
        block_height: u32
    ) -> Self {
        MasternodeList {
            quorums,
            block_hash,
            known_height: Some(block_height),
            masternode_merkle_root: [0u8; 32],
            quorum_merkle_root: [0u8; 32],
            masternodes,
        }
    }

    pub fn calculate_masternode_merkle_root(&self, block_height_lookup: BlockHeightLookup) -> [u8; 32] {
        const EMPTY: [u8; 32] = [0u8; 32];
        if let Some(hashes) = self.hashes_for_merkle_root(block_height_lookup) {
            if hashes.is_empty() { EMPTY }
            if let Some(data) = merkle_root_from_hashes(hashes) {
                if data.is_empty() { EMPTY } else { data }
            }
        }
        EMPTY
    }

    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len();
        }
        count
    }

    pub fn valid_masternodes_for(&self, quorum_modifier: &[u8; 32], quorum_count: u32, block_height_lookup: BlockHeightLookup) -> Vec<MasternodeEntry> {
        let block_height = block_height_lookup(self.block_hash);
        let score_dictionary = self.score_dictionary_for_quorum_modifier(quorum_modifier, block_height);
        let scores: Vec<[u8; 32]> = score_dictionary.into_keys().collect();

        /*NSArray *scores = [[score_dictionary allKeys] sortedArrayUsingComparator:^NSComparisonResult(id _Nonnull obj1, id _Nonnull obj2) {
            UInt256 hash1 = *(UInt256 *)((NSData *)obj1).bytes;
            UInt256 hash2 = *(UInt256 *)((NSData *)obj2).bytes;
            return uint256_sup(hash1, hash2) ? NSOrderedAscending : NSOrderedDescending;
        }];*/
        let mut masternodes: Vec<MasternodeEntry> = Vec::new();
        let masternodes_in_list_count = self.masternodes.len();
        let count = min(masternodes_in_list_count, scores.len());
        for i in 0..count {
            let score = scores[i];
            let masternode = score_dictionary[score];
            if masternode.is_valid_at(block_height) {
                masternodes.push(masternode);
            }
            if masternodes.len() == quorum_count {
                break;
            }
        }
        masternodes
    }

    pub fn score_dictionary_for_quorum_modifier(&self, quorum_modifier: &[u8; 32], block_height: u32) -> BTreeMap<[u8; 32], MasternodeEntry> {
        let score_dict: BTreeMap<[u8; 32], MasternodeEntry> = BTreeMap::new();
        for (_hash, mn_entry) in self.masternodes {
            let score = self.masternode_score(mn_entry, quorum_modifier, block_height);
            if score.is_empty() { continue; }
            score_dict[score] = &mn_entry;
        }
        score_dict
    }

    pub fn masternode_score(&self, masternode_entry: MasternodeEntry, modifier: &[u8; 32], block_height: u32) -> [u8; 32] {
        assert!(masternode_entry);
        if masternode_entry.confirmed_hash_at(block_height) == [0u8; 32] {
            return [0u8; 32];
        }
        let mut data: &[u8] = &[0u8];
        let mut offset = &mut 0;
        if let Some(hash) = masternode_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash_at(block_height) {
            data.write_with(offset, hash);
        }
        data.write_with(offset, modifier);
        sha256_1(data)
    }


    pub fn provider_tx_ordered_hashes(&self) -> Vec<&[u8; 32]> {
        /*let pro_tx_hashes = [self.mSimplifiedMasternodeListDictionaryByReversedRegistrationTransactionHash allKeys];
        pro_tx_hashes = [pro_tx_hashes sortedArrayUsingComparator:^NSComparisonResult(id _Nonnull obj1, id _Nonnull obj2) {
            UInt256 hash1 = *(UInt256 *)((NSData *)obj1).bytes;
            UInt256 hash2 = *(UInt256 *)((NSData *)obj2).bytes;
            return uint256_sup(hash1, hash2) ? NSOrderedDescending : NSOrderedAscending;
        }];*/
        self.masternodes.into_keys().collect()
    }


    pub fn hashes_for_merkle_root(&self, block_height_lookup: BlockHeightLookup) -> Option<Vec<[u8; 32]>> {
        let pro_tx_hashes = self.provider_tx_ordered_hashes();
        let block_height = block_height_lookup(self.block_hash);
        if block_height == u32::MAX {
            println!("Block height lookup queried an unknown block {:?}", self.block_hash);
            None
        } else {
            Some(pro_tx_hashes
                .into_iter()
                .map(|hash| self.masternodes[hash].simplified_masternode_entry_hash_at(block_height))
                .collect())
        }
    }

    pub fn masternode_merkle_root_with(&mut self, block_height_lookup: BlockHeightLookup) -> [u8; 32] {
        if self.masternode_merkle_root == 0 {
            self.masternode_merkle_root = self.calculate_masternode_merkle_root(block_height_lookup);
        }
        return self.masternode_merkle_root;
    }

}
