#![allow(dead_code)]
#![allow(unused_variables)]
#[macro_use]
pub mod processing;
extern crate dash_spv_ffi;
extern crate dash_spv_models;

#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod tests;
mod macros;

use std::slice;
use std::ptr::null_mut;
use byte::BytesExt;
use dash_spv_ffi::ffi::boxer::{boxed, boxed_vec};
use dash_spv_ffi::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHeightByHash, GetBlockHashByHeight, MasternodeListDestroy, MasternodeListLookup, ShouldProcessLLMQTypeCallback, ValidateLLMQCallback, MerkleRootLookup, MasternodeListSave, SaveLLMQSnapshot, GetLLMQSnapshotByBlockHash, LogMessage, HashDestroy, LLMQSnapshotDestroy, SendError, ShouldProcessDiffWithRange};
use dash_spv_ffi::ffi::to::ToFFI;
use dash_spv_ffi::ffi::unboxer::{unbox_any, unbox_block, unbox_qr_info_result, unbox_llmq_snapshot, unbox_llmq_validation_data, unbox_mn_list_diff_result, unbox_masternode_list};
use dash_spv_ffi::types;
use dash_spv_models::llmq;
use dash_spv_models::masternode::LLMQEntry;
use dash_spv_primitives::consensus::encode;
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use crate::processing::{MasternodeProcessor, MNListDiffResult, MasternodeProcessorCache, QRInfoResult, ProcessingError};

/// Destroys anonymous internal holder for UInt256
#[no_mangle]
pub unsafe extern fn processor_destroy_block_hash(block_hash: *mut [u8; 32]) {
    println!("processor_destroy_block_hash: {:?}", block_hash);
    unbox_any(block_hash);
}

/// Destroys types::LLMQValidationData
#[no_mangle]
pub unsafe extern fn processor_destroy_llmq_validation_data(data: *mut types::LLMQValidationData) {
    unbox_llmq_validation_data(data);
}

/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern fn processor_destroy_masternode_list(list: *mut types::MasternodeList) {
    unbox_masternode_list(list);
}

/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern fn processor_destroy_mnlistdiff_result(result: *mut types::MNListDiffResult) {
    unbox_mn_list_diff_result(result);
}

/// Destroys types::LLMQRotationInfoResult
#[no_mangle]
pub unsafe extern fn processor_destroy_qr_info_result(result: *mut types::QRInfoResult) {
    unbox_qr_info_result(result);
}

/// Destroys types::LLMQSnapshot
#[no_mangle]
pub unsafe extern fn processor_destroy_llmq_snapshot(result: *mut types::LLMQSnapshot) {
    unbox_llmq_snapshot(result);
}

/// Destroys types::Block
#[no_mangle]
pub unsafe extern fn processor_destroy_block(result: *mut types::Block) {
    unbox_block(result);
}





/// Register all the callbacks for use across FFI

#[no_mangle]
pub unsafe extern fn register_processor(
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
    send_error: SendError,
    log_message: LogMessage
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
        send_error,
        log_message
    );
    println!("register_processor: {:?}", processor);
    boxed(processor)
}

/// Unregister all the callbacks for use across FFI
#[no_mangle]
pub unsafe extern fn unregister_processor(processor: *mut MasternodeProcessor) {
    println!("unregister_processor: {:?}", processor);
    let unboxed = unbox_any(processor);
    // unbox_any(unboxed.genesis_hash);
}

/// Initialize opaque cache to store needed information between FFI calls
#[no_mangle]
pub unsafe extern fn processor_create_cache() -> *mut MasternodeProcessorCache {
    let cache = MasternodeProcessorCache::default();
    println!("processor_create_cache: {:?}", cache);
    boxed(cache)
}

/// Destroy opaque cache
#[no_mangle]
pub unsafe extern fn processor_destroy_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_destroy_cache: {:?}", cache);
    let cache = unbox_any(cache);
}

/// Read and process message received as a response for 'GETMNLISTDIFF' call
/// Here we calculate quorums according to Core v0.17
/// See https://github.com/dashpay/dips/blob/master/dip-0004.md
#[no_mangle]
pub extern "C" fn process_mnlistdiff_from_message(
    message_arr: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
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
    processor.log(format!("process_mnlistdiff_from_message.start: {:?} {:?} {:p} {:p} {:?}", std::time::Instant::now(), genesis_hash, processor, cache, context));
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let list_diff = unwrap_or_failure!(llmq::MNListDiff::new(message, &mut 0, |hash| processor.lookup_block_height_by_hash(hash)));
    let error = processor.should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash);
    if error != ProcessingError::None.into() {
        processor.log(format!("process_mnlistdiff_from_message.finish_with_error: {:?} {:?}", std::time::Instant::now(), error));
        return boxed(types::MNListDiffResult::default_with_error(error));
    }
    let result = processor.get_list_diff_result_with_base_lookup(list_diff, cache);
    processor.log(format!("process_mnlistdiff_from_message.finish: {:?} {:#?}", std::time::Instant::now(), result));
    boxed(result)
}

/*
/// Read message received as a response for 'GETQRINFO' call
#[no_mangle]
pub extern "C" fn read_qrinfo(
    message_arr: *const u8,
    message_length: usize,
    processor: *mut MasternodeProcessor,
    context: *const std::ffi::c_void,
) -> *mut types::QRInfo {
    let processor = unsafe { &mut *processor };
    processor.opaque_context = context;
    processor.log(format!("read_qrinfo.start: {:?} {:p} {:?}", std::time::Instant::now(), processor, context));
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let block_height_lookup = |hash| processor.lookup_block_height_by_hash(hash);
    let read_list_diff = |offset: &mut usize| llmq::MNListDiff::new(message, offset, block_height_lookup);
    let read_snapshot = |offset: &mut usize| types::LLMQSnapshot::from_bytes(message, offset);
    let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(message, offset);
    let offset = &mut 0;
    let snapshot_at_h_c = boxed(unwrap_or_qr_failure!(read_snapshot(offset)));
    let snapshot_at_h_2c = boxed(unwrap_or_qr_failure!(read_snapshot(offset)));
    let snapshot_at_h_3c = boxed(unwrap_or_qr_failure!(read_snapshot(offset)));
    let mn_list_diff_tip = boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode());
    let mn_list_diff_at_h = boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode());
    let mn_list_diff_at_h_c = boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode());
    let mn_list_diff_at_h_2c = boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode());
    let mn_list_diff_at_h_3c = boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode());
    let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);
    let (snapshot_at_h_4c, mn_list_diff_at_h_4c) = if extra_share {
        (boxed(unwrap_or_qr_failure!(read_snapshot(offset))),
         boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode()))
    } else {
        (null_mut(), null_mut())
    };
    let last_quorum_per_index_count = unwrap_or_qr_failure!(read_var_int(offset)).0 as usize;
    let mut last_quorum_per_index_vec: Vec<*mut types::LLMQEntry> = Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        last_quorum_per_index_vec.push(boxed(unwrap_or_qr_failure!(LLMQEntry::from_bytes(message, offset)).encode()));
    }
    let quorum_snapshot_list_count = unwrap_or_qr_failure!(read_var_int(offset)).0 as usize;
    let mut quorum_snapshot_list_vec: Vec<*mut types::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        quorum_snapshot_list_vec.push(boxed(unwrap_or_qr_failure!(read_snapshot(offset))));
    }
    let mn_list_diff_list_count = unwrap_or_qr_failure!(read_var_int(offset)).0 as usize;
    let mut mn_list_diff_list_vec: Vec<*mut types::MNListDiff> = Vec::with_capacity(mn_list_diff_list_count);
    for _i in 0..mn_list_diff_list_count {
        mn_list_diff_list_vec.push(boxed(unwrap_or_qr_failure!(read_list_diff(offset)).encode()));
    }
    let result = types::QRInfo {
        snapshot_at_h_c,
        snapshot_at_h_2c,
        snapshot_at_h_3c,
        snapshot_at_h_4c,
        mn_list_diff_tip,
        mn_list_diff_at_h,
        mn_list_diff_at_h_c,
        mn_list_diff_at_h_2c,
        mn_list_diff_at_h_3c,
        mn_list_diff_at_h_4c,
        extra_share,
        last_quorum_per_index_count,
        last_quorum_per_index: boxed_vec(last_quorum_per_index_vec),
        quorum_snapshot_list_count,
        quorum_snapshot_list: boxed_vec(quorum_snapshot_list_vec),
        mn_list_diff_list_count,
        mn_list_diff_list: boxed_vec(mn_list_diff_list_vec),
    };
    processor.log(format!("read_qrinfo.finish: {:?} {:#?}", std::time::Instant::now(), result));
    boxed(result)
}

/// Here we calculate quorums according to Core v0.18
/// See https://github.com/dashpay/dips/blob/master/dip-0024.md
#[no_mangle]
pub extern "C" fn process_qrinfo(
    info: *mut types::QRInfo,
    use_insight_as_backup: bool,
    genesis_hash: *const u8,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> *mut types::QRInfoResult {
    let llmq_rotation_info = unsafe { *info };
    let cache = unsafe { &mut *cache };
    let extra_share = llmq_rotation_info.extra_share;
    let processor = unsafe { &mut *processor };
    processor.opaque_context = context;
    processor.use_insight_as_backup = use_insight_as_backup;
    processor.genesis_hash = genesis_hash;
    processor.log(format!("process_qrinfo.start: {:?} {:?} {:p} {:p} {:?}", std::time::Instant::now(), genesis_hash, processor, cache, context));
    let mut process_list_diff = |list_diff: llmq::MNListDiff| processor.get_list_diff_result_with_base_lookup(list_diff, cache);
    let decode_diff = |list_diff: *mut types::MNListDiff| unsafe { (*(list_diff)).decode() };
    let decode_snapshot = |snapshot: *mut types::LLMQSnapshot| unsafe { (*(snapshot)).decode() };
    let mut get_list_diff_result = |list_diff: llmq::MNListDiff| boxed(process_list_diff(list_diff));

    let diff_at_tip = decode_diff(llmq_rotation_info.mn_list_diff_tip);
    let diff_at_h = decode_diff(llmq_rotation_info.mn_list_diff_at_h);
    let diff_at_h_c = decode_diff(llmq_rotation_info.mn_list_diff_at_h_c);
    let diff_at_h_2c = decode_diff(llmq_rotation_info.mn_list_diff_at_h_2c);
    let diff_at_h_3c = decode_diff(llmq_rotation_info.mn_list_diff_at_h_3c);
    let diff_at_h_4c = if extra_share { Some(decode_diff(llmq_rotation_info.mn_list_diff_at_h_4c)) } else { None };

    let snapshot_at_h_c = decode_snapshot(llmq_rotation_info.snapshot_at_h_c);
    let snapshot_at_h_2c = decode_snapshot(llmq_rotation_info.snapshot_at_h_2c);
    let snapshot_at_h_3c = decode_snapshot(llmq_rotation_info.snapshot_at_h_3c);
    let snapshot_at_h_4c = if extra_share { Some(decode_snapshot(llmq_rotation_info.snapshot_at_h_4c)) } else { None };

    processor.save_snapshot(diff_at_h_c.block_hash, snapshot_at_h_c.clone());
    processor.save_snapshot(diff_at_h_2c.block_hash, snapshot_at_h_2c.clone());
    processor.save_snapshot(diff_at_h_3c.block_hash, snapshot_at_h_3c.clone());

    if extra_share {
        processor.save_snapshot(diff_at_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.as_ref().unwrap().clone());
    }

    let result_at_tip = get_list_diff_result(diff_at_tip);
    let result_at_h = get_list_diff_result(diff_at_h);
    let result_at_h_c = get_list_diff_result(diff_at_h_c);
    let result_at_h_2c = get_list_diff_result(diff_at_h_2c);
    let result_at_h_3c = get_list_diff_result(diff_at_h_3c);
    let result_at_h_4c = if extra_share { get_list_diff_result(diff_at_h_4c.unwrap()) } else { null_mut() };

    let last_quorum_per_index_count = llmq_rotation_info.last_quorum_per_index_count;
    let quorum_snapshot_list_count = llmq_rotation_info.quorum_snapshot_list_count;
    let mn_list_diff_list_count = llmq_rotation_info.mn_list_diff_list_count;
    let last_quorum_per_index = llmq_rotation_info.last_quorum_per_index;

    let mut diffs = Vec::<*mut types::MNListDiffResult>::with_capacity(mn_list_diff_list_count);
    for i in 0..mn_list_diff_list_count {
        let list_diff_encoded = unsafe { *llmq_rotation_info.mn_list_diff_list.offset(i as isize) };
        let list_diff = decode_diff(list_diff_encoded);
        let list_diff_block_hash = list_diff.block_hash;
        let list_diff_result = get_list_diff_result(list_diff);
        diffs.push(list_diff_result);
        let snapshot_encoded = unsafe { *llmq_rotation_info.quorum_snapshot_list.offset(i as isize) };
        let snapshot_encoded = decode_snapshot(snapshot_encoded);
        processor.save_snapshot(list_diff_block_hash, snapshot_encoded);
    }

    let result = types::QRInfoResult {
        result_at_tip,
        result_at_h,
        result_at_h_c,
        result_at_h_2c,
        result_at_h_3c,
        result_at_h_4c,
        snapshot_at_h_c: llmq_rotation_info.snapshot_at_h_c,
        snapshot_at_h_2c: llmq_rotation_info.snapshot_at_h_2c,
        snapshot_at_h_3c: llmq_rotation_info.snapshot_at_h_3c,
        snapshot_at_h_4c: llmq_rotation_info.snapshot_at_h_4c,
        extra_share,
        last_quorum_per_index_count,
        last_quorum_per_index,
        quorum_snapshot_list_count,
        quorum_snapshot_list: llmq_rotation_info.quorum_snapshot_list,
        mn_list_diff_list_count,
        mn_list_diff_list: boxed_vec(diffs),
    };
    processor.log(format!("process_qrinfo.finish: {:?} {:#?}", std::time::Instant::now(), result));
    boxed(result)
}
*/

/// Here we read & calculate quorums according to Core v0.18
/// See https://github.com/dashpay/dips/blob/master/dip-0024.md
/// The reason behind we have multiple methods for this is that:
/// in objc we need 2 separate calls to incorporate additional logics between reading and processing
#[no_mangle]
pub extern "C" fn process_qrinfo_from_message(
    message: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
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
    processor.log(format!("process_qrinfo_from_message.start: {:?} {:?} {:?} {:?} {:?}", std::time::Instant::now(), genesis_hash, processor, cache, context));
    let cache = unsafe { &mut *cache };
    let offset = &mut 0;
    let mut process_list_diff = |list_diff: llmq::MNListDiff| processor.get_list_diff_result_with_base_lookup(list_diff, cache);
    let read_list_diff = |offset: &mut usize| processor.read_list_diff_from_message(message, offset);
    let read_snapshot = |offset: &mut usize| llmq::LLMQSnapshot::from_bytes(message, offset);
    let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(message, offset);
    let mut get_list_diff_result = |list_diff: llmq::MNListDiff| boxed(process_list_diff(list_diff));

    let snapshot_at_h_c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let snapshot_at_h_2c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let snapshot_at_h_3c = unwrap_or_qr_result_failure!(read_snapshot(offset));
    let diff_tip = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let error = processor.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash);
    if error != ProcessingError::None.into() {
        processor.log(format!("process_qrinfo_from_message.finish_with_error: {:?} {:#?}", std::time::Instant::now(), error));
        return boxed(types::QRInfoResult::default_with_error(error));
    }
    let diff_h = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_2c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let diff_h_3c = unwrap_or_qr_result_failure!(read_list_diff(offset));
    let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);
    let snapshot_at_h_4c = if extra_share { Some(unwrap_or_qr_result_failure!(read_snapshot(offset))) } else { None };
    let diff_h_4c = if extra_share { Some(unwrap_or_qr_result_failure!(read_list_diff(offset))) } else { None };

    processor.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
    processor.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
    processor.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
    if extra_share {
        processor.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.clone().unwrap());
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

    let last_quorum_per_index_count = 0;//unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut last_quorum_per_index_vec: Vec<*mut types::LLMQEntry> = Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        last_quorum_per_index_vec.push(boxed(unwrap_or_qr_result_failure!(LLMQEntry::from_bytes(message, offset)).encode()));
    }
    let quorum_snapshot_list_count = 0;//unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut quorum_snapshot_list_vec: Vec<*mut types::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    let mut snapshots: Vec<llmq::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        let snapshot = unwrap_or_qr_result_failure!(read_snapshot(offset));
        snapshots.push(snapshot.clone());
    }
    let mn_list_diff_list_count = 0;//unwrap_or_qr_result_failure!(read_var_int(offset)).0 as usize;
    let mut mn_list_diff_list_vec: Vec<*mut types::MNListDiffResult> = Vec::with_capacity(mn_list_diff_list_count);
    assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
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
        snapshot_at_h_4c: if extra_share { boxed(snapshot_at_h_4c.unwrap().encode()) } else { null_mut() },
        extra_share,
        last_quorum_per_index: boxed_vec(last_quorum_per_index_vec),
        last_quorum_per_index_count,
        quorum_snapshot_list: boxed_vec(quorum_snapshot_list_vec),
        quorum_snapshot_list_count,
        mn_list_diff_list: boxed_vec(mn_list_diff_list_vec),
        mn_list_diff_list_count
    };
    processor.log(format!("process_qrinfo_from_message.finish: {:?} {:#?}", std::time::Instant::now(), result));
    boxed(result)
}

/// This is convenience Core v0.17 method for use in tests which doesn't involve cross-FFI calls
pub fn process_mnlistdiff_from_message_internal(
    message_arr: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
    genesis_hash: *const u8,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> MNListDiffResult {
    let processor = unsafe { &mut *processor };
    let cache = unsafe { &mut *cache };
    println!("process_mnlistdiff_from_message_internal.start: {:?}", std::time::Instant::now());
    processor.opaque_context = context;
    processor.use_insight_as_backup = use_insight_as_backup;
    processor.genesis_hash = genesis_hash;
    let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
    let list_diff = unwrap_or_diff_processing_failure!(llmq::MNListDiff::new(message, &mut 0, |hash| processor.lookup_block_height_by_hash(hash)));
    let result = processor.get_list_diff_result_internal_with_base_lookup(list_diff, cache);
    println!("process_mnlistdiff_from_message_internal.finish: {:?} {:#?}", std::time::Instant::now(), result);
    result


}

/// This is convenience Core v0.18 method for use in tests which doesn't involve cross-FFI calls
pub fn process_qrinfo_from_message_internal(
    message: *const u8,
    message_length: usize,
    use_insight_as_backup: bool,
    genesis_hash: *const u8,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> QRInfoResult {
    println!("process_qrinfo_from_message: {:?} {:?}", processor, cache);
    let message: &[u8] = unsafe { slice::from_raw_parts(message, message_length as usize) };
    let processor = unsafe { &mut *processor };
    processor.opaque_context = context;
    processor.use_insight_as_backup = use_insight_as_backup;
    processor.genesis_hash = genesis_hash;
    let cache = unsafe { &mut *cache };
    println!("process_qrinfo_from_message --: {:?} {:?} {:?}", processor, processor.opaque_context, cache);
    let offset = &mut 0;
    let read_list_diff = |offset: &mut usize|
        processor.read_list_diff_from_message(message, offset);
    let mut process_list_diff = |list_diff: llmq::MNListDiff|
        processor.get_list_diff_result_internal_with_base_lookup(list_diff, cache);
    let read_snapshot = |offset: &mut usize| llmq::LLMQSnapshot::from_bytes(message, offset);
    let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(message, offset);
    let snapshot_at_h_c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
    let snapshot_at_h_2c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
    let snapshot_at_h_3c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
    let diff_tip = unwrap_or_qr_processing_failure!(read_list_diff(offset));
    let diff_h = unwrap_or_qr_processing_failure!(read_list_diff(offset));
    let diff_h_c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
    let diff_h_2c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
    let diff_h_3c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
    let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);
    let (snapshot_at_h_4c, diff_h_4c) = if extra_share {
        (Some(unwrap_or_qr_processing_failure!(read_snapshot(offset))),
         Some(unwrap_or_qr_processing_failure!(read_list_diff(offset))))
    } else {
        (None, None)
    };
    processor.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
    processor.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
    processor.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
    if extra_share {
        processor.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.as_ref().unwrap().clone());
    }
    let last_quorum_per_index_count = unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
    let mut last_quorum_per_index: Vec<LLMQEntry> = Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        last_quorum_per_index.push(unwrap_or_qr_processing_failure!(LLMQEntry::from_bytes(message, offset)));
    }
    let quorum_snapshot_list_count = unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
    let mut quorum_snapshot_list: Vec<llmq::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        quorum_snapshot_list.push(unwrap_or_qr_processing_failure!(read_snapshot(offset)));
    }
    let mn_list_diff_list_count = unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
    let mut mn_list_diff_list: Vec<MNListDiffResult> = Vec::with_capacity(mn_list_diff_list_count);
    for _i in 0..mn_list_diff_list_count {
        mn_list_diff_list.push(process_list_diff(unwrap_or_qr_processing_failure!(read_list_diff(offset))));
    }
    // The order is important since the each new one dependent on previous
    let result_at_h_4c = if let Some(diff) = diff_h_4c {
        Some(process_list_diff(diff))
    } else {
        None
    };
    let result_at_h_3c = process_list_diff(diff_h_3c);
    let result_at_h_2c = process_list_diff(diff_h_2c);
    let result_at_h_c = process_list_diff(diff_h_c);
    let result_at_h = process_list_diff(diff_h);
    let result_at_tip = process_list_diff(diff_tip);
    QRInfoResult {
        error_status: ProcessingError::None,
        result_at_tip,
        result_at_h,
        result_at_h_c,
        result_at_h_2c,
        result_at_h_3c,
        result_at_h_4c,
        snapshot_at_h_c,
        snapshot_at_h_2c,
        snapshot_at_h_3c,
        snapshot_at_h_4c,
        extra_share,
        last_quorum_per_index,
        quorum_snapshot_list,
        mn_list_diff_list
    }
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
