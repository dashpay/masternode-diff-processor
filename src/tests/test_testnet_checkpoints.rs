use crate::{process_mnlistdiff_from_message, register_processor};
use crate::common::ChainType;
use crate::lib_tests::tests::{add_insight_lookup_default, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, message_from_file, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, should_process_llmq_of_type, snapshot_destroy_default, validate_llmq_callback};
use crate::tests::block_store::init_testnet_store;

#[test]
fn test_checkpoint_530000() {
    let chain = ChainType::TestNet;
    let context = &mut (FFIContext { chain, is_dip_0024: false, cache: &mut Default::default(), blocks: init_testnet_store() });
    let bytes = message_from_file("MNT530000.dat".to_string());
    let processor = unsafe {
        &mut *register_processor(
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_from_context,
            get_llmq_snapshot_by_block_hash_from_context,
            save_llmq_snapshot_in_cache,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type,
            validate_llmq_callback,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    let result = unsafe {
        *process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            false,
            true,
            70221,
            context.genesis_as_ptr(),
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )
    };

    assert!(result.is_valid(), "Result must be valid");
}