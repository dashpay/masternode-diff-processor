use dash_spv_models::common::ChainType;
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, message_from_file, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, should_process_llmq_of_type, snapshot_destroy_default};
use crate::{process_mnlistdiff_from_message, register_processor};
use crate::tests::block_store::init_mainnet_store;
use crate::tests::json_from_core_snapshot::{list_to_list, MNList};
use crate::tests::llmq_rotation::validate_llmq_callback_throuh_rust_bls;

//#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let context = &mut (FFIContext {
        chain,
        cache: &mut Default::default(),
        blocks: init_mainnet_store()
    });
    let list: MNList = serde_json::from_slice(&message_from_file("MNLIST_1746460.dat".to_string())).unwrap();
    let masternode_list = list_to_list(list);

    let bytes = message_from_file("MNL_1746460_1746516.dat".to_string());
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
            validate_llmq_callback_throuh_rust_bls,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    processor.opaque_context = context as *mut _ as *mut std::ffi::c_void;
    processor.use_insight_as_backup = true;
    processor.genesis_hash = context.genesis_as_ptr();

    processor.save_masternode_list(masternode_list.block_hash, &masternode_list);
    let result = unsafe {
        *process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            false,
            false,
            context.genesis_as_ptr(),
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
    )};
    // rootMNListValid: d3af314676cb2dc2bd605544c8b807ad0dd4f77abd646d941522a58b20f7cbb3 == 3c65e384906b065d26e5715cbce361eeb86c8ebcecd799e35acd7219c9b2c97e
    // LLMQ list root valid: Some(3b16f4499557388f26957264f079cf6e067f5fddb3de2bdee8f151028c319e8d) == Some(3b16f4499557388f26957264f079cf6e067f5fddb3de2bdee8f151028c319e8d)

    assert_diff_result(context, result);

}
