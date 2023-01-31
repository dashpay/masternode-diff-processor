use crate::lib_tests::tests::{add_insight_lookup_default, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, message_from_file, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, should_process_llmq_of_type_actual, snapshot_destroy_default, validate_llmq_callback};
use crate::{process_mnlistdiff_from_message, register_processor};
use crate::chain::common::ChainType;
use crate::tests::block_store::init_mainnet_store;
use crate::tests::json_from_core_snapshot::masternode_list_from_json;

#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let context = &mut (FFIContext {
        chain,
        cache: &mut Default::default(),
        is_dip_0024: false,
        blocks: init_mainnet_store()
    });
    let masternode_list_1761054 = masternode_list_from_json("MNLIST_1761054_1666771101.811508_saveMasternodeList.json".to_string());
    let masternode_list_1761048 = masternode_list_from_json("MNLIST_1761048_1666773093.153379_saveMasternodeList.json".to_string());

    let bytes = message_from_file("MNL_1761054_1761100.dat".to_string());
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
            should_process_llmq_of_type_actual,
            validate_llmq_callback,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    processor.opaque_context = context as *mut _ as *mut std::ffi::c_void;
    processor.use_insight_as_backup = true;
    processor.genesis_hash = context.genesis_as_ptr();

    processor.save_masternode_list(masternode_list_1761048.block_hash, &masternode_list_1761048);
    processor.save_masternode_list(masternode_list_1761054.block_hash, &masternode_list_1761054);
    let result = unsafe {
        *process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            false,
            false,
            70221,
            context.genesis_as_ptr(),
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )};
    // println!("{:#?}", result);
    // assert_diff_result(context, result);
}

