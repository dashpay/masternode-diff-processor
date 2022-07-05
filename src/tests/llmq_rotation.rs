use std::ptr::null_mut;
use dash_spv_models::common::chain_type::ChainType;
use dash_spv_primitives::crypto::byte_util::{Reversable, UInt256};
use dash_spv_primitives::hashes::hex::{FromHex, ToHex};
use crate::lib_tests::tests::{add_insight_lookup, block_height_lookup_5078, FFIContext, get_block_hash_by_height_5078, get_llmq_snapshot_by_block_height, masternode_list_destroy, masternode_list_lookup, message_from_file, should_process_llmq_of_type, validate_llmq_callback};
use crate::{llmq_rotation_info_process2, process_qrinfo_from_message, processor_create_cache, register_processor};

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
        get_block_hash_by_height_5078,
        get_llmq_snapshot_by_block_height,
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
#[test]
fn test_llmq_rotation_2() {
    let bytes = message_from_file("QRINFO_1_8344.dat".to_string());
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let merkle_root = [0u8; 32].as_ptr();
    let use_insight_as_backup= false;
    let base_masternode_list_hash = null_mut();
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;
    println!("test_llmq_rotation_2 {:?}", bytes.to_hex());
    let result = llmq_rotation_info_process2(
        c_array,
        length,
        base_masternode_list_hash,
        merkle_root,
        use_insight_as_backup,
        block_height_lookup_,
        get_block_hash_by_height_5078,
        get_llmq_snapshot_by_block_height,
        masternode_list_lookup,
        masternode_list_destroy,
        add_insight_lookup,
        should_process_llmq_of_type,
        validate_llmq_callback,
        context,
    );
}

unsafe extern "C" fn block_height_lookup_(block_hash: *mut [u8; 32], _context: *const std::ffi::c_void) -> u32 {
    //let bh = block_height_for(chain, masternode_list.block_hash.reversed().to_string().as_str());
    let mut h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    let rev = h.reversed();
    let rev_s = rev.to_string();
    match rev_s.as_str() {
        "00000072f3c73d891d86546f259ba2cd87d1aa655c447640a4257f6a8e6f7018" => 5334,
        "000000a451ba6459b3ce6128a5e8f273f9bc2010645dd4721e1b51efce18dda7" => 4207,
        "000000076aeba26f76a5d0e12e11c9b4d35d7232f1bbae6c47b4d8bef4a12b62" => 4192,
        "00000179987c39850ddd901eec6bfd0a508ec54fb6a0cd28481481aa0adf56b6" => 4168,
        "00000028bd64fd360dba79acf7cb3bae6cea18553c7232894a2ace15ada70940" => 4144,
        "000002410622902b361d1e2194f2072c6409c6f22ef5fea854d3326a27075713" => 4120,
        "000001f340d35fe89d1924de57ccbf63a7a09347835e6e4990ee2df12a4a67f9" => 4096,
        _ => u32::MAX
    }
}

unsafe extern "C" fn get_block_hash_by_height_(block_height: u32, _context: *const std::ffi::c_void) -> *const u8 {
    match block_height {
        5334 => UInt256::from_hex("00000072f3c73d891d86546f259ba2cd87d1aa655c447640a4257f6a8e6f7018").unwrap().reversed().0.as_ptr(),
        4207 => UInt256::from_hex("000000a451ba6459b3ce6128a5e8f273f9bc2010645dd4721e1b51efce18dda7").unwrap().reversed().0.as_ptr(),
        4192 => UInt256::from_hex("000000076aeba26f76a5d0e12e11c9b4d35d7232f1bbae6c47b4d8bef4a12b62").unwrap().reversed().0.as_ptr(),
        4168 => UInt256::from_hex("00000179987c39850ddd901eec6bfd0a508ec54fb6a0cd28481481aa0adf56b6").unwrap().reversed().0.as_ptr(),
        4144 => UInt256::from_hex("00000028bd64fd360dba79acf7cb3bae6cea18553c7232894a2ace15ada70940").unwrap().reversed().0.as_ptr(),
        4120 => UInt256::from_hex("000002410622902b361d1e2194f2072c6409c6f22ef5fea854d3326a27075713").unwrap().reversed().0.as_ptr(),
        4096 => UInt256::from_hex("000001f340d35fe89d1924de57ccbf63a7a09347835e6e4990ee2df12a4a67f9").unwrap().reversed().0.as_ptr(),
        _ => UInt256::MIN.0.as_ptr()
    }
}

#[test]
fn test_llmq_rotation_3() {
    let bytes = message_from_file("QRINFO_0125771d2f9419377aebc77e3b880afaa6f3438ccf247919ce4e9bd450a029343fe9f3a8caf3845251ee9002770cb0f2e1c6f6c43fdff480f7a59f8e29c000000001".to_string());
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let merkle_root = [0u8; 32].as_ptr();
    let use_insight_as_backup= false;
    let base_masternode_list_hash = null_mut();
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;
    println!("test_llmq_rotation_3 {:?}", bytes.to_hex());
    let result = llmq_rotation_info_process2(
        c_array,
        length,
        base_masternode_list_hash,
        merkle_root,
        use_insight_as_backup,
        block_height_lookup_,
        get_block_hash_by_height_5078,
        get_llmq_snapshot_by_block_height,
        masternode_list_lookup,
        masternode_list_destroy,
        add_insight_lookup,
        should_process_llmq_of_type,
        validate_llmq_callback,
        context,
    );
}


unsafe extern "C" fn block_height_lookup_333(block_hash: *mut [u8; 32], _context: *const std::ffi::c_void) -> u32 {
    let h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    match orig_s.as_str() {
        "df111a9253e9f2f80d3de7a7274aaaa6d5ac0426b6a048991fc8ed7586000000" => 22030,
        "4a53ef88bad2a12b5af9767bcef10980955971826b5f75ef0f17518a73020000" => 21976,
        "ef176a4a5dbbb041f7e582e4adac44c81e7d1efdc92c2b532bcaa24106000000" => 21928,
        "1efab5ab1fe9d99f90072d7d377b0271511e16b2f833b3314576ae23e4030000" => 21880,
        "88d5f21114fddb86c8ab230f2b45fd90b8cfa7a61b0d819160fdb08345040000" => 21832,
        "5b298e3fcc475e57f20520601057e3686219a2bbe09b0baa34d9759268050000" => 21784,
        "0b06e90c32f0611bce49e4646213f0bb7a43c59b82cc5a87295bf4f15a060000" => 21984,
        "7b9b8fe254a17c31a2315171b8b224ccf2ddf7960d69a87c5400514d19050000" => 22008,
        "af5509f7e1a2c9827eac9487746dd6f363ac56d4659fdf0089f8bca54f020000" => 21936,
        "c970d99fa088f3a1e9bc9eb3b9a4d03263b755149ce39a6db5bdff6d23090000" => 21960,
        "4887de631c97d933c8a52026589ad02aa31ad2a9e6fd66c8b278aa34bd060000" => 21912,
        "99867fdccf5f7b50c648b1ad3c93c1fa7515d4529aa5efde1ad17e0780050000" => 21888,
        "2323ab4e88e0923e8e3bd506192dcaa4286c20340cc7525128665941ac050000" => 21840,
        "e30d315d4a40d82d059a65a900242f393b50ff8fefde58a4a1b482d232010000" => 21864,
        "c90366c6455c23930215ce724062fa1dd2ae89b66c722302dc9d56ba1d030000" => 21792,
        "dbe354545727c9db4cf872765455d1aff09296a14daa4075d18db6bb4a030000" => 21816,
        "4d523423dc19a438e57ee0e150c3f62369063a1bf99274083bd2f055fe020000" => 21768,
        "c244b2775b5fd5ec60d911f7b851ec4e78cf54f678f3d64cc69245fe60070000" => 21744,
        "36a179a25d081bc6836be48b11f10e6e484fd0ef068dd315a9e11482ea030000" => 21696,
        "cd36d310de9b14823aa9aedc00abbe2b5ac4117cb8d00f7693ad22af05060000" => 21720,
        _ => u32::MAX
    }
}

#[test]
fn test_devnet_333() {
    // let bytes = message_from_file("qrinfo--1-20737.dat".to_string());
    let bytes = message_from_file("QRINFO_1_21976.dat".to_string());
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;
    let merkle_root = UInt256::from_hex("0df2b5537f108386f42acbd9f7b5aa5dfab907b83c0212c7074e1209f2d78ddf").unwrap();
    let result = llmq_rotation_info_process2(
        bytes.as_ptr(),
        bytes.len(),
        null_mut(),
        merkle_root.0.as_ptr(),
        false,
        block_height_lookup_333,
        get_block_hash_by_height_5078,
        get_llmq_snapshot_by_block_height,
        masternode_list_lookup,
        masternode_list_destroy,
        add_insight_lookup,
        should_process_llmq_of_type,
        validate_llmq_callback,
        context
    );
}

unsafe extern "C" fn get_merkle_root_by_hash(block_hash: *mut [u8; 32], _context: *const std::ffi::c_void) -> *const u8 {
    UInt256::from_hex("0df2b5537f108386f42acbd9f7b5aa5dfab907b83c0212c7074e1209f2d78ddf").unwrap().0.as_ptr()
}

#[test]
fn test_processor_devnet_333() {
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash,
            block_height_lookup_333,
            get_block_hash_by_height_5078,
            get_llmq_snapshot_by_block_height,
            masternode_list_lookup,
            masternode_list_destroy,
            add_insight_lookup,
            should_process_llmq_of_type,
            validate_llmq_callback,
        )
    };
    let cache = unsafe { processor_create_cache() };
    let bytes = message_from_file("QRINFO_1_21976.dat".to_string());
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;

    let result = process_qrinfo_from_message(
        bytes.as_ptr(),
        bytes.len(),
        null_mut(),
        // UInt256::from_hex("0df2b5537f108386f42acbd9f7b5aa5dfab907b83c0212c7074e1209f2d78ddf").unwrap().0.as_ptr(),
        false,
        processor,
        cache,
        context
    );
}
