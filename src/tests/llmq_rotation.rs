use std::ptr::null_mut;
use crate::common::chain_type::ChainType;
use crate::lib_tests::tests::{add_insight_lookup, block_height_lookup_5078, FFIContext, masternode_list_destroy, masternode_list_lookup, message_from_file, should_process_llmq_of_type, validate_llmq_callback};
use crate::llmq_rotation_info_process2;

#[test]
fn test_llmq_rotation() {
    let bytes = message_from_file("qrinfo--1-5078.dat".to_string());
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let merkle_root = [0u8; 32].as_ptr();
    let use_insight_as_backup= false;
    let base_masternode_list_hash = null_mut();
    let h = 5078;
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;
    let result = llmq_rotation_info_process2(
        c_array,
        length,
        base_masternode_list_hash,
        merkle_root,
        use_insight_as_backup,
        block_height_lookup_5078,
        masternode_list_lookup,
        masternode_list_destroy,
        add_insight_lookup,
        should_process_llmq_of_type,
        validate_llmq_callback,
        context,
    );
    println!("{:?}", result);
    let result_5078 = unsafe { *result };
    let result_at_h = unsafe { *result_5078.result_at_h };
    assert!(result_at_h.has_found_coinbase, "Did not find coinbase at height {}", h);
    // turned off on purpose as we don't have the coinbase block
    // assert!(result.valid_coinbase, "Coinbase not valid at height {}", h);
    // assert!(result_at_h.has_valid_mn_list_root, "mn list root not valid at height {}", h);
    // assert!(result_at_h.has_valid_llmq_list_root, "LLMQ list root not valid at height {}", h);
    // assert!(result_at_h.has_valid_quorums, "validQuorums not valid at height {}", h);
}
