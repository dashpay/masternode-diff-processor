use dash_spv_ffi::ffi::from::FromFFI;
use dash_spv_models::common::chain_type::ChainType;
use dash_spv_primitives::crypto::byte_util::UInt256;
use dash_spv_primitives::hashes::hex::FromHex;
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, block_height_lookup_122088, FFIContext, get_block_hash_by_height_default, get_llmq_snapshot_by_block_hash_default, get_masternode_list_by_block_hash_default, get_merkle_root_by_hash_default, masternode_list_destroy_default, masternode_list_save_default, message_from_file, save_llmq_snapshot_default, should_process_llmq_of_type, validate_llmq_callback};
use crate::{MasternodeProcessorCache, process_mnlistdiff_from_message, processor_create_cache, register_processor};

#[test]
fn test_mnl_saving_to_disk() { // testMNLSavingToDisk
    let chain = ChainType::TestNet;
    let bytes = message_from_file("ML_at_122088.dat".to_string());
    let context = &mut (FFIContext { chain, cache: MasternodeProcessorCache::default() }) as *mut _ as *mut std::ffi::c_void;

    let cache = unsafe { processor_create_cache() };
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash_default,
            block_height_lookup_122088,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            get_masternode_list_by_block_hash_default,
            masternode_list_save_default,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type,
            validate_llmq_callback,
        )
    };

    let result = process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        false,
        processor,
        cache,
        context
    );
    println!("{:?}", result);
    let result = unsafe { *result };
    let block_hash = UInt256(unsafe { *result.block_hash });
    let masternode_list = unsafe { *result.masternode_list };
    let masternode_list_decoded = unsafe { masternode_list.decode() };
    assert_eq!(
        UInt256::from_hex("94d0af97187af3b9311c98b1cf40c9c9849df0af55dc63b097b80d4cf6c816c5").unwrap(),
        masternode_list_decoded.masternode_merkle_root.unwrap(),
        "MNList merkle root should be valid");
    assert_diff_result(chain, result);
}
