#![allow(dead_code)]
#![allow(unused_variables)]
// pub extern crate bitcoin_hashes as hashes;
// pub extern crate secp256k1;

#[macro_use]
pub mod crypto;
pub mod ffi;
pub mod processing;

#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod tests;

use std::slice;
use std::ffi::c_void;
use dash_spv_models::common::llmq_type::LLMQType;
use dash_spv_primitives::crypto::byte_util::{ConstDecodable, UInt256};
use ffi::wrapped_types::{AddInsightBlockingLookup, BlockHeightLookup, MasternodeListDestroy, MasternodeListLookup, ShouldProcessLLMQTypeCallback, ValidateLLMQCallback};
use crate::ffi::boxer::{boxed, boxed_vec};
use crate::ffi::from::FromFFI;
use crate::ffi::to::{encode_masternodes_map, encode_quorums_map, ToFFI};
use crate::ffi::types::{LLMQRotationInfoResult, LLMQValidationData, MNListDiffResult};
use crate::ffi::unboxer::{unbox_any, unbox_llmq_rotation_info, unbox_llmq_rotation_info_result, unbox_llmq_validation_data, unbox_result};
use crate::processing::{LLMQSnapshot, MNListDiff};
use crate::processing::manager::Manager;

fn failure<'a>() -> *mut ffi::types::MNListDiffResult {
    boxed(MNListDiffResult::default())
}
fn qr_failure() -> *mut ffi::types::LLMQRotationInfoResult {
    boxed(ffi::types::LLMQRotationInfoResult::default())
}

pub fn mnl_diff_process<
    BHL: Fn(UInt256) -> u32 + Copy,
    MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
>(
    message_arr: *const u8,
    message_length: usize,
    base_masternode_list_hash: *const u8,
    merkle_root: *const u8,
    use_insight_as_backup: bool,
    block_height_lookup: BHL,
    masternode_list_lookup: MNL,
    masternode_list_destroy: MasternodeListDestroy,
    add_insight_lookup: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq_callback: ValidateLLMQCallback,
    context: *const c_void, // External Masternode Manager Diff Message Context ()
) -> *mut MNListDiffResult {
    println!("mnl_diff_process.start: {:?}", std::time::Instant::now());
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let desired_merkle_root = match UInt256::from_const(merkle_root) {
        Some(data) => data,
        None => { return failure(); }
    };
    let list_diff = match MNListDiff::new(message, &mut 0, block_height_lookup) {
        Some(data) => data,
        None => { return failure(); }
    };
    let base_masternode_list_hash = if base_masternode_list_hash.is_null() { None } else { UInt256::from_const(base_masternode_list_hash) };
    // println!("mnl_diff_process: {:?}", base_masternode_list_hash);
    let manager = Manager {
        block_height_lookup,
        masternode_list_lookup,
        masternode_list_destroy: |list: *const ffi::types::MasternodeList| unsafe { masternode_list_destroy(list) },
        add_insight_lookup: |hash: UInt256| unsafe { add_insight_lookup(boxed(hash.0), context) },
        should_process_llmq_of_type: |llmq_type: LLMQType| unsafe { should_process_llmq_of_type(llmq_type.into(), context) },
        validate_llmq_callback: |data: LLMQValidationData| unsafe { validate_llmq_callback(boxed(data), context) },
        use_insight_as_backup,
        base_masternode_list_hash
    };
    let result = MNListDiffResult::from_diff(list_diff, manager, desired_merkle_root);
    println!("mnl_diff_process.finish: {:?}", std::time::Instant::now());
    boxed(result)
}

#[no_mangle]
pub extern "C" fn mndiff_process(
    message_arr: *const u8,
    message_length: usize,
    base_masternode_list_hash: *const u8,
    merkle_root: *const u8,
    use_insight_as_backup: bool,
    block_height_lookup: BlockHeightLookup,
    masternode_list_lookup: MasternodeListLookup,
    masternode_list_destroy: MasternodeListDestroy,
    add_insight_lookup: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq_callback: ValidateLLMQCallback,
    context: *const c_void, // External Masternode Manager Diff Message Context ()
) -> *mut MNListDiffResult {
    mnl_diff_process(
        message_arr,
        message_length,
        base_masternode_list_hash,
        merkle_root,
        use_insight_as_backup,
        |hash: UInt256| unsafe { block_height_lookup(boxed(hash.0), context) },
        |hash: UInt256| unsafe { masternode_list_lookup(boxed(hash.0), context) },
        masternode_list_destroy,
        add_insight_lookup,
        should_process_llmq_of_type,
        validate_llmq_callback,
        context,
    )
}

#[no_mangle]
pub unsafe extern fn mndiff_block_hash_destroy(block_hash: *mut [u8; 32]) {
    unbox_any(block_hash);
}

#[no_mangle]
pub unsafe extern fn mndiff_quorum_validation_data_destroy(data: *mut ffi::types::LLMQValidationData) {
    unbox_llmq_validation_data(data);
}

#[no_mangle]
pub unsafe extern fn mndiff_destroy(result: *mut MNListDiffResult) {
    unbox_result(result);
}


#[no_mangle]
pub extern "C" fn llmq_rotation_info_read(
    message_arr: *const u8,
    message_length: usize,
    block_height_lookup: BlockHeightLookup,
    context: *const c_void, // External Masternode Manager Diff Message Context ()
) -> *mut ffi::types::LLMQRotationInfo {
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    boxed(ffi::types::LLMQRotationInfo::new(message, block_height_lookup, context)
        .unwrap_or(ffi::types::LLMQRotationInfo::default()))
}
#[no_mangle]
pub extern "C" fn llmq_rotation_info_process(
    info: *mut ffi::types::LLMQRotationInfo,
    base_masternode_list_hash: *const u8,
    merkle_root: *const u8,
    use_insight_as_backup: bool,
    block_height_lookup: BlockHeightLookup,
    masternode_list_lookup: MasternodeListLookup,
    masternode_list_destroy: MasternodeListDestroy,
    add_insight_lookup: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq_callback: ValidateLLMQCallback,
    context: *const c_void, // External Masternode Manager Diff Message Context ()
) -> *mut ffi::types::LLMQRotationInfoResult {
    let llmq_rotation_info = unsafe { *info };
    let desired_merkle_root = match UInt256::from_const(merkle_root) {
        Some(data) => data,
        None => { return qr_failure(); }
    };
    let base_masternode_list_hash = if base_masternode_list_hash.is_null() { None } else { UInt256::from_const(base_masternode_list_hash) };
    let manager = Manager {
        block_height_lookup: |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) },
        masternode_list_lookup: |hash: UInt256| unsafe { masternode_list_lookup(boxed(hash.0), context) },
        masternode_list_destroy: |list: *const ffi::types::MasternodeList| unsafe { masternode_list_destroy(list) },
        add_insight_lookup: |hash: UInt256| unsafe { add_insight_lookup(boxed(hash.0), context) },
        should_process_llmq_of_type: |llmq_type: LLMQType| unsafe { should_process_llmq_of_type(llmq_type.into(), context) },
        validate_llmq_callback: |data: LLMQValidationData| unsafe { validate_llmq_callback(boxed(data), context) },
        use_insight_as_backup,
        base_masternode_list_hash
    };
    boxed(LLMQRotationInfoResult::new(llmq_rotation_info, manager, desired_merkle_root))
}

#[no_mangle]
pub extern "C" fn llmq_rotation_info_process2(
    message_arr: *const u8,
    message_length: usize,
    base_masternode_list_hash: *const u8,
    merkle_root: *const u8,
    use_insight_as_backup: bool,
    block_height_lookup: BlockHeightLookup,
    masternode_list_lookup: MasternodeListLookup,
    masternode_list_destroy: MasternodeListDestroy,
    add_insight_lookup: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq_callback: ValidateLLMQCallback,
    context: *const c_void, // External Masternode Manager Diff Message Context ()
) -> *mut ffi::types::LLMQRotationInfoResult {
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let desired_merkle_root = match UInt256::from_const(merkle_root) {
        Some(data) => data,
        None => { return qr_failure(); }
    };
    let base_masternode_list_hash = if base_masternode_list_hash.is_null() { None } else { UInt256::from_const(base_masternode_list_hash) };
    let manager = Manager {
        block_height_lookup: |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) },
        masternode_list_lookup: |hash: UInt256| unsafe { masternode_list_lookup(boxed(hash.0), context) },
        masternode_list_destroy: |list: *const ffi::types::MasternodeList| unsafe { masternode_list_destroy(list) },
        add_insight_lookup: |hash: UInt256| unsafe { add_insight_lookup(boxed(hash.0), context) },
        should_process_llmq_of_type: |llmq_type: LLMQType| unsafe { should_process_llmq_of_type(llmq_type.into(), context) },
        validate_llmq_callback: |data: LLMQValidationData| unsafe { validate_llmq_callback(boxed(data), context) },
        use_insight_as_backup,
        base_masternode_list_hash
    };

    let result = LLMQRotationInfoResult::from_message(message, desired_merkle_root, manager);

    boxed(result.unwrap_or(LLMQRotationInfoResult::default()))
}

#[no_mangle]
pub unsafe extern fn llmq_rotation_info_destroy(result: *mut ffi::types::LLMQRotationInfo) {
    unbox_llmq_rotation_info(result);
}

#[no_mangle]
pub unsafe extern fn llmq_rotation_info_result_destroy(result: *mut ffi::types::LLMQRotationInfoResult) {
    unbox_llmq_rotation_info_result(result);
}
