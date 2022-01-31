use std::collections::{BTreeMap, HashMap};
use crate::CoinbaseTransaction;
use crate::common::llmq_type::LLMQType;
use crate::crypto::byte_util::{merkle_root_from_hashes, Reversable, UInt256};
use crate::masternode::llmq_entry::LLMQEntry;
use crate::masternode::masternode_entry::MasternodeEntry;

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
            .field("quorum_merkle_root", &self.llmq_merkle_root)
            .field("masternodes", &self.masternodes.len())
            .field("quorums", &self.quorums.len())
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
                        .cmp(&h2.clone()
                            .reversed()));
            let mns = self.masternodes.clone();
            let entry_hashes = pro_tx_hashes
                .clone()
                .into_iter()
                .map(|hash| {
                    let h = hash.clone();
                    let map = mns.clone();
                    let mn = &map[&h];
                    let entry_hash = mn.masternode_entry_hash_at(block_height);
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
