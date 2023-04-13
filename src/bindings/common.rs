use std::ffi::CString;
use std::os::raw::c_char;
use crate::crypto::byte_util::ConstDecodable;
use crate::crypto::UInt256;
use crate::ffi::boxer::boxed;
use crate::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup, SaveLLMQSnapshot, ShouldProcessDiffWithRange, ShouldProcessLLMQTypeCallback};
use crate::ffi::unboxer::{unbox_any, unbox_block, unbox_llmq_snapshot, unbox_llmq_validation_data, unbox_masternode_list, unbox_mn_list_diff_result, unbox_qr_info_result, unbox_vec_ptr};
use crate::processing::{MasternodeProcessor, MasternodeProcessorCache};
use crate::types;

/// Register all the callbacks for use across FFI
/// # Safety
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
    destroy_hash: HashDestroy,
    destroy_snapshot: LLMQSnapshotDestroy,
    should_process_diff_with_range: ShouldProcessDiffWithRange,
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
        // validate_llmq,
        destroy_hash,
        destroy_snapshot,
        should_process_diff_with_range,
        // log_message,
    );
    println!("register_processor: {:?}", processor);
    boxed(processor)
}

/// Unregister all the callbacks for use across FFI
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unregister_processor(processor: *mut MasternodeProcessor) {
    println!("unregister_processor: {:?}", processor);
    let unboxed = unbox_any(processor);
    // unbox_any(unboxed.genesis_hash);
}

/// Initialize opaque cache to store needed information between FFI calls
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_create_cache() -> *mut MasternodeProcessorCache {
    let cache = MasternodeProcessorCache::default();
    println!("processor_create_cache: {:?}", cache);
    boxed(cache)
}

/// Destroy opaque cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_destroy_cache: {:?}", cache);
    let cache = unbox_any(cache);
}

/// Remove models list from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_masternode_list_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_masternode_list_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Some(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_masternode_list(&hash);
    }
}

/// Remove quorum snapshot from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_llmq_snapshot_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_llmq_snapshot_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Some(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_snapshot(&hash);
    }
}

/// Remove llmq members from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_llmq_members_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_llmq_members_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Some(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_quorum_members(&hash);
    }
}

/// Remove quorum snapshot from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_clear_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_clear_cache: {:p}", cache);
    (*cache).clear();
}



/// Destroys anonymous internal holder for UInt256
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_block_hash(block_hash: *mut [u8; 32]) {
    unbox_any(block_hash);
}

/// Destroys anonymous internal holder for UInt256
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_byte_array(data: *const u8, len: usize) {
    unbox_vec_ptr(data as *mut u8, len);
}

/// Destroys types::LLMQValidationData
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_llmq_validation_data(
    data: *mut types::LLMQValidationData,
) {
    unbox_llmq_validation_data(data);
}

/// # Safety
/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_masternode_list(list: *mut types::MasternodeList) {
    unbox_masternode_list(list);
}

/// Destroys types::MNListDiffResult
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_mnlistdiff_result(result: *mut types::MNListDiffResult) {
    unbox_mn_list_diff_result(result);
}

/// Destroys types::LLMQRotationInfoResult
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_qr_info_result(result: *mut types::QRInfoResult) {
    unbox_qr_info_result(result);
}

/// Destroys types::LLMQSnapshot
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_llmq_snapshot(result: *mut types::LLMQSnapshot) {
    unbox_llmq_snapshot(result);
}

/// Destroys types::Block
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_block(result: *mut types::Block) {
    unbox_block(result);
}

// Here we have temporary replacement for DSKey from the DashSync
/// Destroys rust-allocated string
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}

/// Destroys UInt160
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_uint160(ptr: *mut [u8; 20]) {
    unbox_any(ptr);
}
