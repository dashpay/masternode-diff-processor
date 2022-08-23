use std::collections::BTreeMap;
use std::ptr::null_mut;
use dash_spv_ffi::ffi::from::FromFFI;
use dash_spv_ffi::ffi::to::ToFFI;
use dash_spv_ffi::types;
use dash_spv_models::common::chain_type::ChainType;
use dash_spv_models::masternode;
use dash_spv_primitives::crypto::byte_util::UInt256;
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, block_height_lookup_default, FFIContext, get_block_hash_by_height_default, get_llmq_snapshot_by_block_hash_default, get_merkle_root_by_hash_default, log_default, masternode_list_destroy_default, message_from_file, save_llmq_snapshot_default, should_process_llmq_of_type, validate_llmq_callback};
use crate::{process_mnlistdiff_from_message, processor_create_cache, register_processor};
use crate::processing::MasternodeProcessorCache;

#[test]
fn test_mainnet_reload_with_processor() {
    let chain = ChainType::MainNet;
    let files = vec![
        "MNL_0_1090944.dat".to_string(),
        "MNL_1090944_1091520.dat".to_string(),
        "MNL_1091520_1091808.dat".to_string(),
        "MNL_1091808_1092096.dat".to_string(),
        "MNL_1092096_1092336.dat".to_string(),
        "MNL_1092336_1092360.dat".to_string(),
        "MNL_1092360_1092384.dat".to_string(),
        "MNL_1092384_1092408.dat".to_string(),
        "MNL_1092408_1092432.dat".to_string(),
        "MNL_1092432_1092456.dat".to_string(),
        "MNL_1092456_1092480.dat".to_string(),
        "MNL_1092480_1092504.dat".to_string(),
        "MNL_1092504_1092528.dat".to_string(),
        "MNL_1092528_1092552.dat".to_string(),
        "MNL_1092552_1092576.dat".to_string(),
        "MNL_1092576_1092600.dat".to_string(),
        "MNL_1092600_1092624.dat".to_string(),
        "MNL_1092624_1092648.dat".to_string(),
        "MNL_1092648_1092672.dat".to_string(),
        "MNL_1092672_1092696.dat".to_string(),
        "MNL_1092696_1092720.dat".to_string(),
        "MNL_1092720_1092744.dat".to_string(),
        "MNL_1092744_1092768.dat".to_string(),
        "MNL_1092768_1092792.dat".to_string(),
        "MNL_1092792_1092816.dat".to_string(),
        "MNL_1092816_1092840.dat".to_string(),
        "MNL_1092840_1092864.dat".to_string(),
        "MNL_1092864_1092888.dat".to_string(),
        "MNL_1092888_1092916.dat".to_string(),
    ];
    let (success, lists) = load_masternode_lists_for_files_new(files, chain);
    assert!(success, "Unsuccessful");
    assert_eq!(lists.len(), 29, "There should be 29 masternode lists");
}

unsafe extern "C" fn masternode_list_lookup(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> *const types::MasternodeList {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    if let Some(list) = data.cache.mn_lists.get(&h) {
        println!("masternode_list_lookup: {}: masternodes: {} quorums: {} mn_merkle_root: {:?}, llmq_merkle_root: {:?}", h, list.masternodes.len(), list.quorums.len(), list.masternode_merkle_root, list.llmq_merkle_root);
        let encoded = list.encode();
        &encoded as *const types::MasternodeList
    } else {
        null_mut()
    }
}


unsafe extern "C" fn masternode_list_save(block_hash: *mut [u8; 32], masternode_list: *const types::MasternodeList, context: *const std::ffi::c_void) -> bool {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let masternode_list = *masternode_list;
    let masternode_list_decoded = masternode_list.decode();
    println!("masternode_list_save: {}", h);
    data.cache.mn_lists.insert(h, masternode_list_decoded);
    true
}

pub fn load_masternode_lists_for_files_new(files: Vec<String>, chain: ChainType) -> (bool, BTreeMap<UInt256, masternode::MasternodeList>) {
    let cache = unsafe { processor_create_cache() };
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash_default,
            block_height_lookup_default,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            masternode_list_lookup,
            masternode_list_save,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type,
            validate_llmq_callback,
            log_default,
        )
    };
    for file in files {
        println!("load_masternode_lists_for_files: [{}]", file);
        let bytes = message_from_file(file);
        let context = &mut (FFIContext { chain, cache: MasternodeProcessorCache::default() }) ;
        let result = process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            false,
            processor,
            cache,
            context as *mut _ as *mut std::ffi::c_void
        );
        let result = unsafe { *result };
        println!("result: [{:?}]", result);
        //println!("MNDiff: {} added, {} modified", result.added_masternodes_count, result.modified_masternodes_count);
        assert_diff_result(chain, result);
        let block_hash = UInt256(unsafe { *result.block_hash });
        let masternode_list = unsafe { *result.masternode_list };
        let masternode_list_decoded = unsafe { masternode_list.decode() };
    }
    let c = unsafe { (*cache).clone() };
    (true, c.mn_lists)
}
