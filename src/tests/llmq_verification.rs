use std::collections::BTreeMap;
use std::ptr::null_mut;
use dash_spv_ffi::ffi::from::FromFFI;
use dash_spv_ffi::ffi::to::ToFFI;
use dash_spv_ffi::types;
use dash_spv_models::common::chain_type::ChainType;
use dash_spv_models::common::LLMQType;
use dash_spv_models::masternode::LLMQEntry;
use dash_spv_primitives::crypto::byte_util::{Reversable, UInt256};
use dash_spv_primitives::hashes::hex::ToHex;
use crate::{process_mnlistdiff_from_message, processor_create_cache, register_processor};
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, block_height_for, block_height_lookup_default, FFIContext, get_block_hash_by_height_default, get_llmq_snapshot_by_block_hash_default, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, message_from_file, save_llmq_snapshot_default, should_process_llmq_of_type, validate_llmq_callback};
use crate::processing::MasternodeProcessorCache;


#[test]
fn testnet_llmq_verification() { //testTestnetQuorumVerification
    let bytes = message_from_file("MNL_0_122928.dat".to_string());
    let merkle_root = [0u8; 32].as_ptr();
    let use_insight_as_backup= false;
    let chain = ChainType::TestNet;
    let base_masternode_list_hash: *const u8 = null_mut();
    let context = &mut FFIContext { chain, cache: MasternodeProcessorCache::default() } as *mut _ as *mut std::ffi::c_void;
    let cache = unsafe { processor_create_cache() };
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash_default,
            block_height_lookup_default,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type,
            validate_llmq_callback,
            log_default,
        )
    };
    let result = process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        use_insight_as_backup,
        processor,
        cache,
        context
    );
    println!("{:?}", result);
    let result_119064 = unsafe { *result };
    assert_diff_result(chain, result_119064);
    let is_valid = result_119064.is_valid();
    println!("is_valid: {}", is_valid);
    if is_valid {
        let bytes = message_from_file("MNL_122928_123000.dat".to_string());
        let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
        let masternode_list_119064 = unsafe { *result_119064.masternode_list };
        let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
        let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();
        let result = process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            use_insight_as_backup,
            processor,
            cache,
            context
        );
        println!("{:?}", result);
        let result_119200 = unsafe { *result };
        assert_diff_result(chain, result_119200);
        let masternode_list_119200 = unsafe { *result_119200.masternode_list };
        let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
        let added_quorums = (0..result_119200.added_llmq_type_maps_count)
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, i| unsafe {
                let map = *(*(result_119200.added_llmq_type_maps.offset(i as isize)));
                let llmq_type = LLMQType::from(map.llmq_type);
                let entry_map = (0..map.count)
                    .into_iter()
                    .fold(BTreeMap::new(), |mut hacc, j| {
                        let raw_entry = *(*(map.values.offset(j as isize)));
                        let entry = raw_entry.decode();
                        hacc.insert(entry.llmq_hash, entry);
                        hacc
                    });
                acc.insert(llmq_type, entry_map);
                acc
            });
        let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = added_quorums.into_iter().filter(|(_, map)| map.contains_key(&block_hash_119064)).collect();
        assert!(hmm.len() > 0, "There should be a quorum using 119064");
        // assert!(added_quorums.contains_key(&block_hash_119064), "There should be a quorum using 119064");
        // TODO: verify with QuorumValidationData (need implement BLS before)
        //let quorum_to_verify = added_quorums[&block_hash_119064];
        //quorum_to_verify.validate_with_masternode_list(masternode_list_119064_decoded);
        //assert!(quorum_to_verify.verified, "Unable to verify quorum");
    }
}

unsafe extern "C" fn get_block_height_by_hash(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> u32 {
    block_height_for((&mut *(context as *mut FFIContext)).chain, UInt256(*(block_hash)).reversed().0.to_hex().as_str())
}

unsafe extern "C" fn get_masternode_list_by_block_hash_119064(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> *const types::MasternodeList {
    let ctx = &mut *(context as *mut FFIContext);
    let h = UInt256(*(block_hash));
    if let Some(list) = ctx.cache.mn_lists.get(&h) {
        let encoded = list.encode();
        &encoded as *const types::MasternodeList
    } else {
        null_mut()
    }
}

pub unsafe extern "C" fn masternode_list_save_119064(block_hash: *mut [u8; 32], masternode_list: *const types::MasternodeList, context: *const std::ffi::c_void) -> bool {
    let ctx = &mut *(context as *mut FFIContext);
    let h = UInt256(*(block_hash));
    let list = (*masternode_list).decode();
    // ctx.cache.mn_lists.insert(h, list);
    true
}

#[test]
fn testnet_llmq_verification_using_processor_and_cache() { //testTestnetQuorumVerification
    let bytes = message_from_file("MNL_0_122928.dat".to_string());
    let use_insight_as_backup= false;
    let chain = ChainType::TestNet;
    let context = &mut FFIContext { chain, cache: MasternodeProcessorCache::default() };
    let processor = unsafe { register_processor(
        get_merkle_root_by_hash_default,
        get_block_height_by_hash,
        get_block_hash_by_height_default,
        get_llmq_snapshot_by_block_hash_default,
        save_llmq_snapshot_default,
        get_masternode_list_by_block_hash_119064,
        masternode_list_save_119064,
        masternode_list_destroy_default,
        add_insight_lookup_default,
        should_process_llmq_of_type,
        validate_llmq_callback,
        log_default)
    };
    let cache = unsafe { processor_create_cache() };

    let result = process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        use_insight_as_backup,
        processor,
        cache,
        context as *mut _ as *mut std::ffi::c_void
    );

    println!("{:?}", result);
    let result_119064 = unsafe { *result };
    assert_diff_result(chain, result_119064);
    let is_valid = result_119064.is_valid();
    println!("is_valid: {}", is_valid);
    if is_valid {
        let bytes = message_from_file("MNL_122928_123000.dat".to_string());
        let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
        let masternode_list_119064 = unsafe { *result_119064.masternode_list };
        let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
        let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();
        //context.cache.mn_lists.insert(block_hash_119064, masternode_list_119064_decoded);

        let result = process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            // block_hash_119064.0.as_ptr(),
            use_insight_as_backup,
            processor,
            cache,
            context as *mut _ as *mut std::ffi::c_void
        );

        println!("{:?}", result);
        let result_119200 = unsafe { *result };
        assert_diff_result(chain, result_119200);
        let masternode_list_119200 = unsafe { *result_119200.masternode_list };
        let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
        let added_quorums = (0..result_119200.added_llmq_type_maps_count)
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, i| unsafe {
                let map = *(*(result_119200.added_llmq_type_maps.offset(i as isize)));
                let llmq_type = LLMQType::from(map.llmq_type);
                let entry_map = (0..map.count)
                    .into_iter()
                    .fold(BTreeMap::new(), |mut hacc, j| {
                        let raw_entry = *(*(map.values.offset(j as isize)));
                        let entry = raw_entry.decode();
                        hacc.insert(entry.llmq_hash, entry);
                        hacc
                    });
                acc.insert(llmq_type, entry_map);
                acc
            });
        let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = added_quorums.into_iter().filter(|(_, map)| map.contains_key(&block_hash_119064)).collect();
        assert!(hmm.len() > 0, "There should be a quorum using 119064");
        // assert!(added_quorums.contains_key(&block_hash_119064), "There should be a quorum using 119064");
        // TODO: verify with QuorumValidationData (need implement BLS before)
        //let quorum_to_verify = added_quorums[&block_hash_119064];
        //quorum_to_verify.validate_with_masternode_list(masternode_list_119064_decoded);
        //assert!(quorum_to_verify.verified, "Unable to verify quorum");
    }
}
