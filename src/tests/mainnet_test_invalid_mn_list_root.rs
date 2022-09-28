use dash_spv_models::common::ChainType;
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, message_from_file, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, should_process_llmq_of_type, snapshot_destroy_default};
use crate::{process_mnlistdiff_from_message, register_processor};
use crate::tests::block_store::init_mainnet_store;
use crate::tests::llmq_rotation::validate_llmq_callback_throuh_rust_bls;

#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let blocks = init_mainnet_store();
    let context = &mut (FFIContext {
        chain,
        cache: &mut Default::default(),
        blocks
    });
    let bytes = message_from_file("MNL_1742805_1745187.dat".to_string());
    let processor = unsafe {
        register_processor(
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
            validate_llmq_callback_throuh_rust_bls,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    let result = process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        false,
        false,
        context.genesis_as_ptr(),
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    );
    let result_1745187 = unsafe { *result };
    assert_diff_result(context, result_1745187);

}
