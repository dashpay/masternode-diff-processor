use std::ptr::null_mut;
use crate::{boxed, boxed_vec, ffi, LLMQType, Manager, ToFFI, UInt256};
use crate::ffi::types::LLMQValidationData;
use crate::masternode::masternode_list;
use crate::processing::manager;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MNListDiffResult {
    pub block_hash: *mut [u8; 32],
    pub has_found_coinbase: bool, //1 byte
    pub has_valid_coinbase: bool, //1 byte
    pub has_valid_mn_list_root: bool, //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool, //1 byte
    pub masternode_list: *mut ffi::types::MasternodeList,
    pub added_masternodes: *mut *mut ffi::types::MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes: *mut *mut ffi::types::MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_llmq_type_maps: *mut *mut ffi::types::LLMQMap,
    pub added_llmq_type_maps_count: usize,
    pub needed_masternode_lists:  *mut *mut [u8; 32], // [u8; 32]
    pub needed_masternode_lists_count: usize,
}

impl MNListDiffResult {
    pub fn from_diff<
        MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
        MND: Fn(*const ffi::types::MasternodeList) + Copy,
        AIL: Fn(UInt256) + Copy,
        BHL: Fn(UInt256) -> u32 + Copy,
        SPL: Fn(LLMQType) -> bool + Copy,
        VQL: Fn(LLMQValidationData) -> bool + Copy,
    >(
        list_diff: crate::processing::mn_list_diff::MNListDiff,
        manager: Manager<BHL, MNL, MND, AIL, SPL, VQL>,
        merkle_root: UInt256,
    ) -> Self {
        let block_hash = list_diff.block_hash;
        let (base_masternodes,
            base_quorums) =
            manager::lookup_masternodes_and_quorums_for(
                manager.base_masternode_list_hash,
                manager.masternode_list_lookup,
                manager.masternode_list_destroy);
        let block_height = list_diff.block_height;
        let coinbase_transaction = list_diff.coinbase_transaction;
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (added_masternodes,
            modified_masternodes,
            masternodes) = manager::classify_masternodes(
            base_masternodes,
            list_diff.added_or_modified_masternodes,
            list_diff.deleted_masternode_hashes,
            block_height,
            block_hash
        );
        println!("MNListDiffResult.from_diff.base_quorums: \n[{:?}] \nadded_quorums:\n [{:?}]", base_quorums.clone(), list_diff.added_quorums.clone());
        let (added_quorums,
            quorums,
            has_valid_quorums,
            needed_masternode_lists) = manager::classify_quorums(
            base_quorums,
            list_diff.added_quorums,
            list_diff.deleted_quorums,
            manager
        );
        println!("MNListDiffResult.from_diff.added_quorums: \n[{:?}] \nquorums:\n [{:?}]", added_quorums.clone(), quorums.clone());
        let masternode_list = masternode_list::MasternodeList::new(masternodes, quorums, block_hash, block_height, quorums_active);
        let has_valid_mn_list_root = masternode_list.has_valid_mn_list_root(&coinbase_transaction);
        let tree_element_count = list_diff.total_transactions;
        let hashes = list_diff.merkle_hashes;
        let flags = list_diff.merkle_flags;
        let has_found_coinbase = coinbase_transaction.has_found_coinbase(hashes);
        let merkle_tree = crate::MerkleTree { tree_element_count, hashes, flags };
        let has_valid_quorum_list_root = !quorums_active || masternode_list.has_valid_llmq_list_root(&coinbase_transaction);
        let needed_masternode_lists_count = needed_masternode_lists.len();
        MNListDiffResult {
            block_hash: boxed(list_diff.block_hash.clone().0),
            has_found_coinbase,
            has_valid_coinbase: merkle_tree.has_root(merkle_root),
            has_valid_mn_list_root,
            has_valid_llmq_list_root: has_valid_quorum_list_root,
            has_valid_quorums,
            masternode_list: boxed(masternode_list.encode()),
            added_masternodes: crate::encode_masternodes_map(&added_masternodes),
            added_masternodes_count: added_masternodes.len(),
            modified_masternodes: crate::encode_masternodes_map(&modified_masternodes),
            modified_masternodes_count: modified_masternodes.len(),
            added_llmq_type_maps: crate::encode_quorums_map(&added_quorums),
            added_llmq_type_maps_count: added_quorums.len(),
            needed_masternode_lists: boxed_vec(needed_masternode_lists),
            needed_masternode_lists_count
        }
    }

    pub fn is_valid(&self) -> bool {
        self.has_found_coinbase && self.has_valid_quorums && self.has_valid_mn_list_root && self.has_valid_llmq_list_root
    }

}

impl Default for MNListDiffResult {
    fn default() -> Self {
        MNListDiffResult {
            block_hash: null_mut(),
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes: null_mut(),
            modified_masternodes_count: 0,
            added_llmq_type_maps: null_mut(),
            added_llmq_type_maps_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0
        }
    }
}
