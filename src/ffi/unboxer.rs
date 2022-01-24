use crate::ffi::wrapped_types::{LLMQMap, MasternodeEntry, MasternodeList, MndiffResult, QuorumEntry, QuorumRotationInfo, QuorumSnapshot, QuorumValidationData};
use crate::wrapped_types::{CoinbaseTransaction, LLMQTypedHash, MNListDiff, Transaction, TransactionInput, TransactionOutput};

pub unsafe fn unbox_any<T: ?Sized>(any: *mut T) -> Box<T> {
    Box::from_raw(any)
}

pub unsafe fn unbox_vec<T>(vec: Vec<*mut T>) -> Vec<Box<T>> {
    vec.iter().map(|&x| unbox_any(x)).collect()
}

pub unsafe fn unbox_vec_ptr<T>(ptr: *mut T, count: usize) -> Vec<T> {
    Vec::from_raw_parts(ptr, count, count)
}

pub unsafe fn unbox_masternode_entry(x: *mut MasternodeEntry) {
    let entry = unbox_any(x);
    unbox_any(entry.confirmed_hash);
    if !entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
        unbox_any(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash);
    }
    unbox_any(entry.key_id_voting);
    unbox_any(entry.masternode_entry_hash);
    unbox_any(entry.operator_public_key);
    unbox_vec_ptr(entry.previous_masternode_entry_hashes, entry.previous_masternode_entry_hashes_count);
    unbox_vec_ptr(entry.previous_operator_public_keys, entry.previous_operator_public_keys_count);
    unbox_vec_ptr(entry.previous_validity, entry.previous_validity_count);
    unbox_any(entry.provider_registration_transaction_hash);
    unbox_any(entry.ip_address);
}

pub unsafe fn unbox_quorum_entry(x: *mut QuorumEntry) {
    let entry = unbox_any(x);
    unbox_any(entry.all_commitment_aggregated_signature);
    if !entry.commitment_hash.is_null() {
        unbox_any(entry.commitment_hash);
    }

    unbox_any(entry.quorum_entry_hash);
    unbox_any(entry.quorum_hash);
    unbox_any(entry.quorum_public_key);
    unbox_any(entry.quorum_threshold_signature);
    unbox_any(entry.quorum_verification_vector_hash);
    let signers_bitset = std::ptr::slice_from_raw_parts_mut(entry.signers_bitset, entry.signers_bitset_length);
    let valid_members_bitset = std::ptr::slice_from_raw_parts_mut(entry.valid_members_bitset, entry.valid_members_bitset_length);
    unbox_any(signers_bitset as *mut [u8]);
    unbox_any(valid_members_bitset as *mut [u8]);
}

pub unsafe fn unbox_llmq_map(x: *mut LLMQMap) {
    let entry = unbox_any(x);
    let values = unbox_vec_ptr(entry.values, entry.count);
    for &x in values.iter() {
        unbox_quorum_entry(x);
    }
}
pub unsafe fn unbox_masternode_list(masternode_list: Box<MasternodeList>) {
    unbox_any(masternode_list.block_hash);
    if !masternode_list.masternode_merkle_root.is_null() {
        unbox_any(masternode_list.masternode_merkle_root);
    }
    if !masternode_list.quorum_merkle_root.is_null() {
        unbox_any(masternode_list.quorum_merkle_root);
    }
    unbox_masternode_vec(unbox_vec_ptr(masternode_list.masternodes, masternode_list.masternodes_count));
    unbox_llmq_map_vec(unbox_vec_ptr(masternode_list.quorum_type_maps, masternode_list.quorum_type_maps_count));
}

pub unsafe fn unbox_masternode_vec(vec: Vec<*mut MasternodeEntry>) {
    for &x in vec.iter() {
        unbox_masternode_entry(x);
    }
}
pub unsafe fn unbox_quorum_vec(vec: Vec<*mut QuorumEntry>) {
    for &x in vec.iter() {
        unbox_quorum_entry(x);
    }
}

pub unsafe fn unbox_llmq_map_vec(vec: Vec<*mut LLMQMap>) {
    for &x in vec.iter() {
        unbox_llmq_map(x);
    }
}

pub unsafe fn unbox_llmq_hash_vec(vec: Vec<*mut LLMQTypedHash>) {
    for &x in vec.iter() {
        unbox_llmq_typed_hash(x);
    }
}

pub unsafe fn unbox_llmq_typed_hash(typed_hash: *mut LLMQTypedHash) {
    let hash = unbox_any(typed_hash);
    unbox_any(hash.llmq_hash);
}

pub unsafe fn unbox_quorum_validation_data(quorum_validation_data: *mut QuorumValidationData) {
    let result = unbox_any(quorum_validation_data);
    unbox_any(result.all_commitment_aggregated_signature);
    unbox_any(result.commitment_hash);
    unbox_any(result.quorum_public_key);
    unbox_any(result.quorum_threshold_signature);
    unbox_vec(unbox_vec_ptr(result.items, result.count));
}

pub unsafe fn unbox_snapshot_vec(vec: Vec<*mut QuorumSnapshot>) {
    for &x in vec.iter() {
        unbox_quorum_snapshot(x);
    }
}

pub unsafe fn unbox_mnlist_diff_vec(vec: Vec<*mut MNListDiff>) {
    for &x in vec.iter() {
        unbox_mnlist_diff(x);
    }
}

pub unsafe fn unbox_quorum_snapshot(quorum_snapshot: *mut QuorumSnapshot) {
    let result = unbox_any(quorum_snapshot);
    unbox_vec_ptr(result.member_list, result.member_list_length);
}
pub unsafe fn unbox_tx_input(result: *mut TransactionInput) {
    let input = unbox_any(result);
    unbox_any(input.input_hash);
    if !input.script.is_null() && input.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.script, input.script_length) as *mut [u8]);
    }
    if !input.signature.is_null() && input.signature_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.signature, input.signature_length) as *mut [u8]);
    }
}
pub unsafe fn unbox_tx_output(result: *mut TransactionOutput) {
    let output = unbox_any(result);
    if !output.script.is_null() && output.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(output.script, output.script_length) as *mut [u8]);
    }
    if !output.address.is_null() && output.address_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(output.address, output.address_length) as *mut [u8]);
    }
}
pub unsafe fn unbox_tx_input_vec(result: Vec<*mut TransactionInput>) {
    for &x in result.iter() {
        unbox_tx_input(x);
    }
}
pub unsafe fn unbox_tx_output_vec(result: Vec<*mut TransactionOutput>) {
    for &x in result.iter() {
        unbox_tx_output(x);
    }
}
pub unsafe fn unbox_tx(result: *mut Transaction) {
    let tx = unbox_any(result);
    unbox_tx_input_vec(unbox_vec_ptr(tx.inputs, tx.inputs_count));
    unbox_tx_output_vec(unbox_vec_ptr(tx.outputs, tx.outputs_count));
    unbox_any(tx.tx_hash);
}

pub unsafe fn unbox_coinbase_tx(result: *mut CoinbaseTransaction) {
    let ctx = unbox_any(result);
    unbox_tx(ctx.base);
    unbox_any(ctx.merkle_root_mn_list);
    if !ctx.merkle_root_llmq_list.is_null() {
        unbox_any(ctx.merkle_root_llmq_list);
    }
}

pub unsafe fn unbox_result(result: *mut MndiffResult) {
    let res = unbox_any(result);
    unbox_masternode_list(unbox_any(res.masternode_list));
    unbox_vec(unbox_vec_ptr(res.needed_masternode_lists, res.needed_masternode_lists_count));
    unbox_masternode_vec(unbox_vec_ptr(res.added_masternodes, res.added_masternodes_count));
    unbox_masternode_vec(unbox_vec_ptr(res.modified_masternodes, res.modified_masternodes_count));
    unbox_llmq_map_vec(unbox_vec_ptr(res.added_quorum_type_maps, res.added_quorum_type_maps_count));
}
pub unsafe fn unbox_mnlist_diff(result: *mut MNListDiff) {
    let list_diff = unbox_any(result);
    unbox_any(list_diff.base_block_hash);
    unbox_any(list_diff.block_hash);
    unbox_any(std::ptr::slice_from_raw_parts_mut(list_diff.merkle_hashes, list_diff.merkle_hashes_count) as *mut [u8]);
    unbox_any(std::ptr::slice_from_raw_parts_mut(list_diff.merkle_flags, list_diff.merkle_flags_count) as *mut [u8]);
    unbox_coinbase_tx(list_diff.coinbase_transaction);

    unbox_vec(unbox_vec_ptr(list_diff.deleted_masternode_hashes, list_diff.deleted_masternode_hashes_count));
    unbox_masternode_vec(unbox_vec_ptr(list_diff.added_or_modified_masternodes, list_diff.added_or_modified_masternodes_count));
    unbox_llmq_hash_vec(unbox_vec_ptr(list_diff.deleted_quorums, list_diff.deleted_quorums_count));

    unbox_quorum_vec(unbox_vec_ptr(list_diff.added_quorums, list_diff.added_quorums_count));
}

pub unsafe fn unbox_qrinfo(result: *mut QuorumRotationInfo) {
    let res = unbox_any(result);
    unbox_quorum_snapshot(res.snapshot_at_h_c);
    unbox_quorum_snapshot(res.snapshot_at_h_2c);
    unbox_quorum_snapshot(res.snapshot_at_h_3c);
    unbox_mnlist_diff(res.list_diff_tip);
    unbox_mnlist_diff(res.list_diff_at_h);
    unbox_mnlist_diff(res.list_diff_at_h_c);
    unbox_mnlist_diff(res.list_diff_at_h_2c);
    unbox_mnlist_diff(res.list_diff_at_h_3c);
    if res.extra_share {
        unbox_quorum_snapshot(res.snapshot_at_h_4c);
        unbox_mnlist_diff(res.list_diff_at_h_4c);
    }
    unbox_vec(unbox_vec_ptr(res.block_hash_list, res.block_hash_list_num as usize));
    unbox_snapshot_vec(unbox_vec_ptr(res.snapshot_list, res.snapshot_list_num as usize));
    unbox_mnlist_diff_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_num as usize));
}
