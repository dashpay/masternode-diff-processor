use std::ffi::c_void;
use std::ptr::null_mut;
use crate::{AddInsightBlockingLookup, BlockHeightLookup, boxed, boxed_vec, ffi, MasternodeListDestroy, MasternodeListLookup, ShouldProcessLLMQTypeCallback, ToFFI, UInt256, ValidateLLMQCallback};
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
    pub added_quorums: *mut *mut ffi::types::LLMQEntry,
    pub added_quorums_count: usize,
    pub needed_masternode_lists:  *mut *mut [u8; 32], // [u8; 32]
    pub needed_masternode_lists_count: usize,
}

impl MNListDiffResult {
    pub fn from_diff(
        list_diff: crate::processing::mn_list_diff::MNListDiff,
        masternode_list_lookup: MasternodeListLookup,
        masternode_list_destroy: MasternodeListDestroy,
        merkle_root: UInt256,
        use_insight_as_backup: bool,
        add_insight_lookup: AddInsightBlockingLookup,
        should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
        validate_llmq_callback: ValidateLLMQCallback,
        block_height_lookup: BlockHeightLookup,
        context: *const c_void, // External Masternode Manager Diff Message Context ()
    ) -> Self {
        let bh_lookup = |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) };
        let block_hash = list_diff.block_hash;
        let (base_masternodes,
            base_quorums) =
            manager::lookup_masternodes_and_quorums_for(
                block_hash,
                masternode_list_lookup,
                masternode_list_destroy,
                context);
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
        let (added_quorums,
            quorums,
            has_valid_quorums,
            needed_masternode_lists) = manager::classify_quorums(
            base_quorums,
            list_diff.added_quorums,
            list_diff.deleted_quorums,
            masternode_list_lookup,
            masternode_list_destroy,
            use_insight_as_backup,
            add_insight_lookup,
            should_process_llmq_of_type,
            validate_llmq_callback,
            block_height_lookup,
            context
        );
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
            block_hash: boxed(list_diff.block_hash.0),
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
            added_quorums: crate::encode_quorums_map(&added_quorums),
            added_quorums_count: added_quorums.len(),
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
            added_quorums: null_mut(),
            added_quorums_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0
        }
    }
}
