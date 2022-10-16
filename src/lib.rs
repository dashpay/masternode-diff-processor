#![allow(dead_code)]
#![allow(unused_variables)]
#[macro_use]
pub mod processing;
extern crate dash_spv_ffi;
extern crate dash_spv_models;

#[cfg(test)]
mod lib_tests;
mod macros;
#[cfg(test)]
mod tests;

use crate::processing::{MasternodeProcessor, MasternodeProcessorCache, ProcessingError};
use byte::BytesExt;
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::callbacks::{
    AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash,
    GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, LogMessage,
    MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup,
    SaveLLMQSnapshot, ShouldProcessDiffWithRange, ShouldProcessLLMQTypeCallback,
    ValidateLLMQCallback,
};
use dash_spv_ffi::ffi::to::ToFFI;
use dash_spv_ffi::ffi::unboxer::{
    unbox_any, unbox_block, unbox_llmq_snapshot, unbox_llmq_validation_data, unbox_masternode_list,
    unbox_mn_list_diff_result, unbox_qr_info_result,
};
use dash_spv_ffi::types;
use dash_spv_models::llmq;
use dash_spv_models::masternode::LLMQEntry;
use dash_spv_primitives::consensus::encode;
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, ConstDecodable};
use std::ptr::null_mut;
use std::slice;
use dash_spv_primitives::crypto::UInt256;

/// Destroys anonymous internal holder for UInt256
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_block_hash(block_hash: *mut [u8; 32]) {
    unbox_any(block_hash);
}

/// Destroys types::LLMQValidationData
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_llmq_validation_data(
    data: *mut types::LLMQValidationData,
) {
    unbox_llmq_validation_data(data);
}

/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_masternode_list(list: *mut types::MasternodeList) {
    unbox_masternode_list(list);
}

/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_mnlistdiff_result(result: *mut types::MNListDiffResult) {
    unbox_mn_list_diff_result(result);
}

/// Destroys types::LLMQRotationInfoResult
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_qr_info_result(result: *mut types::QRInfoResult) {
    unbox_qr_info_result(result);
}

/// Destroys types::LLMQSnapshot
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_llmq_snapshot(result: *mut types::LLMQSnapshot) {
    unbox_llmq_snapshot(result);
}

/// Destroys types::Block
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_block(result: *mut types::Block) {
    unbox_block(result);
}

/// Register all the callbacks for use across FFI

#[no_mangle]
pub unsafe extern "C" fn register_processor(
    get_merkle_root_by_hash: MerkleRootLookup,
    get_block_height_by_hash: GetBlockHeightByHash,
    get_block_hash_by_height: GetBlockHashByHeight,
    get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
    save_llmq_snapshot: SaveLLMQSnapshot,
    get_masternode_list_by_block_hash: MasternodeListLookup,
    save_masternode_list: MasternodeListSave,
    destroy_masternode_list: MasternodeListDestroy,
    add_insight: AddInsightBlockingLookup,
    should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
    validate_llmq: ValidateLLMQCallback,
    destroy_hash: HashDestroy,
    destroy_snapshot: LLMQSnapshotDestroy,
    should_process_diff_with_range: ShouldProcessDiffWithRange,
    log_message: LogMessage,
) -> *mut MasternodeProcessor {
    let processor = MasternodeProcessor::new(
        get_merkle_root_by_hash,
        get_block_height_by_hash,
        get_block_hash_by_height,
        get_llmq_snapshot_by_block_hash,
        save_llmq_snapshot,
        get_masternode_list_by_block_hash,
        save_masternode_list,
        destroy_masternode_list,
        add_insight,
        should_process_llmq_of_type,
        validate_llmq,
        destroy_hash,
        destroy_snapshot,
        should_process_diff_with_range,
        log_message,
    );
    println!("register_processor: {:?}", processor);
    boxed(processor)
}

/// Unregister all the callbacks for use across FFI
#[no_mangle]
pub unsafe extern "C" fn unregister_processor(processor: *mut MasternodeProcessor) {
    println!("unregister_processor: {:?}", processor);
    let unboxed = unbox_any(processor);
    // unbox_any(unboxed.genesis_hash);
}

/// Initialize opaque cache to store needed information between FFI calls
#[no_mangle]
pub unsafe extern "C" fn processor_create_cache() -> *mut MasternodeProcessorCache {
    let cache = MasternodeProcessorCache::default();
    println!("processor_create_cache: {:?}", cache);
    boxed(cache)
}

/// Destroy opaque cache
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_destroy_cache: {:?}", cache);
    let cache = unbox_any(cache);
}

/// Remove masternode list from cache
#[no_mangle]
pub unsafe extern "C" fn processor_remove_masternode_list_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_masternode_list_from_cache_for_block_hash: {:?} {:?}", block_hash, cache);
    if let Some(hash) = UInt256::from_const(block_hash) {
        (&mut *cache).remove_masternode_list(hash);
    }
}

/// Remove quorum snapshot from cache
#[no_mangle]
pub unsafe extern "C" fn processor_remove_llmq_snapshot_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_llmq_snapshot_from_cache_for_block_hash: {:?} {:?}", block_hash, cache);
    if let Some(hash) = UInt256::from_const(block_hash) {
        (&mut *cache).remove_snapshot(hash);
    }
}
/// Remove quorum snapshot from cache
#[no_mangle]
pub unsafe extern "C" fn processor_clear_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_clear_cache: {:?}", cache);
    (&mut *cache).clear();
}
/// Read and process message received as a response for 'GETMNLISTDIFF' call
/// Here we calculate quorums according to Core v0.17
/// See https://github.com/dashpay/dips/blob/master/dip-0004.md
#[no_mangle]
pub extern "C" fn process_mnlistdiff_from_message(
    message_arr: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
    is_from_snapshot: bool,
    genesis_hash: *const u8,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> *mut types::MNListDiffResult {
    let cache = unsafe { &mut *cache };
    let processor = unsafe { &mut *processor };
    processor.opaque_context = context;
    processor.use_insight_as_backup = use_insight_as_backup;
    processor.genesis_hash = genesis_hash;
    processor.log(format!(
        "process_mnlistdiff_from_message.start: {:?} {:?} {:p} {:p} {:?}",
        std::time::Instant::now(),
        genesis_hash,
        processor,
        cache,
        context
    ));
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let list_diff = unwrap_or_failure!(llmq::MNListDiff::new(message, &mut 0, |hash| processor
        .lookup_block_height_by_hash(hash)));
    processor.log(format!(
        "process_mnlistdiff_from_message.list_diff: {}..{} {}..{}",
        list_diff.base_block_height,
        list_diff.block_height,
        list_diff.base_block_hash,
        list_diff.block_hash,
    ));
    if !is_from_snapshot {
        let error = processor
            .should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash);
        let none_error: u8 = ProcessingError::None.into();
        if error != none_error {
            processor.log(format!(
                "process_mnlistdiff_from_message.finish_with_error: {:?} {:?}",
                std::time::Instant::now(),
                error
            ));
            return boxed(types::MNListDiffResult::default_with_error(error));
        }
    }
    let result = processor.get_list_diff_result_with_base_lookup(list_diff, cache);
    processor.log(format!(
        "process_mnlistdiff_from_message.finish: {:?} {:#?}",
        std::time::Instant::now(),
        result
    ));
    boxed(result)
}

/// Here we read & calculate quorums according to Core v0.18
/// See https://github.com/dashpay/dips/blob/master/dip-0024.md
/// The reason behind we have multiple methods for this is that:
/// in objc we need 2 separate calls to incorporate additional logics between reading and processing
#[no_mangle]
pub extern "C" fn process_qrinfo_from_message(
    message: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
    is_from_snapshot: bool,
    genesis_hash: *const u8,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> *mut types::QRInfoResult {
    let message: &[u8] = unsafe { slice::from_raw_parts(message, message_length as usize) };
    let processor = unsafe { &mut *processor };
    processor.opaque_context = context;
    processor.use_insight_as_backup = use_insight_as_backup;
    processor.genesis_hash = genesis_hash;
    processor.log(format!(
        "process_qrinfo_from_message.start: {:?} {:?} {:?} {:?} {:?}",
        std::time::Instant::now(),
        genesis_hash,
        processor,
        cache,
        context
    ));
    let cache = unsafe { &mut *cache };
    let offset = &mut 0;
    let mut process_list_diff = |list_diff: llmq::MNListDiff| {
        processor.get_list_diff_result_with_base_lookup(list_diff, cache)
    };
    let read_list_diff =
        |offset: &mut usize| processor.read_list_diff_from_message(message, offset);
    let read_snapshot = |offset: &mut usize| llmq::LLMQSnapshot::from_bytes(message, offset);
    let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(message, offset);
    let mut get_list_diff_result =
        |list_diff: llmq::MNListDiff| boxed(process_list_diff(list_diff));

    let snapshot_at_h_c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let snapshot_at_h_2c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let snapshot_at_h_3c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let diff_tip = unwrap_or_qr_result_failure!(read_list_diff(offset));
    processor.log(format!(
        "process_qrinfo_from_message.list_diff: {}..{} {}..{}",
        diff_tip.base_block_height,
        diff_tip.block_height,
        diff_tip.base_block_hash,
        diff_tip.block_hash,
    ));
    if !is_from_snapshot {
        let error =
            processor.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash);
        let none_error: u8 = ProcessingError::None.into();
        if error != none_error {
            processor.log(format!(
                "process_qrinfo_from_message.finish_with_error: {:?} {:#?}",
                std::time::Instant::now(),
                error
            ));
            return boxed(types::QRInfoResult::default_with_error(error));
        }
    }
    let diff_h = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_2c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_3c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);
    let snapshot_at_h_4c = if extra_share {
        Some(unwrap_or_qr_result_failure!(read_snapshot(offset)))
    } else {
        None
    };
    let diff_h_4c = if extra_share {
        Some(unwrap_or_qr_result_failure!(read_list_diff(offset)))
    } else {
        None
    };

    processor.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
    processor.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
    processor.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
    if extra_share {
        processor.save_snapshot(
            diff_h_4c.as_ref().unwrap().block_hash,
            snapshot_at_h_4c.clone().unwrap(),
        );
    }

    let result_at_tip = get_list_diff_result(diff_tip);
    let result_at_h = get_list_diff_result(diff_h);
    let result_at_h_c = get_list_diff_result(diff_h_c);
    let result_at_h_2c = get_list_diff_result(diff_h_2c);
    let result_at_h_3c = get_list_diff_result(diff_h_3c);
    let result_at_h_4c = if extra_share {
        get_list_diff_result(diff_h_4c.unwrap())
    } else {
        null_mut()
    };

    let last_quorum_per_index_count = 0; //unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut last_quorum_per_index_vec: Vec<*mut types::LLMQEntry> =
        Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        last_quorum_per_index_vec.push(boxed(
            unwrap_or_qr_result_failure!(LLMQEntry::from_bytes(message, offset)).encode(),
        ));
    }
    let quorum_snapshot_list_count = 0; //unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut quorum_snapshot_list_vec: Vec<*mut types::LLMQSnapshot> =
        Vec::with_capacity(quorum_snapshot_list_count);
    let mut snapshots: Vec<llmq::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        let snapshot = unwrap_or_qr_result_failure!(read_snapshot(offset));
        snapshots.push(snapshot.clone());
    }
    let mn_list_diff_list_count = 0; //unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut mn_list_diff_list_vec: Vec<*mut types::MNListDiffResult> =
        Vec::with_capacity(mn_list_diff_list_count);
    assert_eq!(
        quorum_snapshot_list_count, mn_list_diff_list_count,
        "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'"
    );
    for i in 0..mn_list_diff_list_count {
        let list_diff = unwrap_or_qr_result_failure!(read_list_diff(offset));
        let block_hash = list_diff.block_hash.clone();
        mn_list_diff_list_vec.push(get_list_diff_result(list_diff));
        let snapshot = snapshots.get(i).unwrap();
        quorum_snapshot_list_vec.push(boxed(snapshot.encode()));
        processor.save_snapshot(block_hash, snapshot.clone());
    }

    let result = types::QRInfoResult {
        error_status: ProcessingError::None.into(),
        result_at_tip,
        result_at_h,
        result_at_h_c,
        result_at_h_2c,
        result_at_h_3c,
        result_at_h_4c,
        snapshot_at_h_c: boxed(snapshot_at_h_c.encode()),
        snapshot_at_h_2c: boxed(snapshot_at_h_2c.encode()),
        snapshot_at_h_3c: boxed(snapshot_at_h_3c.encode()),
        snapshot_at_h_4c: if extra_share {
            boxed(snapshot_at_h_4c.unwrap().encode())
        } else {
            null_mut()
        },
        extra_share,
        last_quorum_per_index: boxed_vec(last_quorum_per_index_vec),
        last_quorum_per_index_count,
        quorum_snapshot_list: boxed_vec(quorum_snapshot_list_vec),
        quorum_snapshot_list_count,
        mn_list_diff_list: boxed_vec(mn_list_diff_list_vec),
        mn_list_diff_list_count,
    };
    processor.log(format!(
        "process_qrinfo_from_message.finish: {:?} {:#?}",
        std::time::Instant::now(),
        result
    ));
    boxed(result)
}

// #[no_mangle]
// pub extern "C" fn test_func(get_masternode_list_by_block_hash: MasternodeListLookup, destroy_masternode_list: MasternodeListDestroy, opaque_context: *const std::ffi::c_void) {
//     let block_hash = UInt256::MIN;
//     dash_spv_ffi::ffi::callbacks::lookup_masternode_list(
//         block_hash,
//         |h: UInt256| unsafe { (get_masternode_list_by_block_hash)(boxed(h.0), opaque_context) },
//         |list: *mut types::MasternodeList| unsafe { (destroy_masternode_list)(list) });
//
// }
