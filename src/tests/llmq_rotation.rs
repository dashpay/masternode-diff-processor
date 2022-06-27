use std::ptr::null_mut;
use dash_spv_models::common::chain_type::ChainType;
use dash_spv_primitives::crypto::byte_util::{Reversable, UInt256};
use dash_spv_primitives::hashes::hex::{FromHex, ToHex};
use crate::lib_tests::tests::{add_insight_lookup, block_height_lookup_5078, FFIContext, get_block_hash_by_height_5078, get_llmq_snapshot_by_block_height, masternode_list_destroy, masternode_list_lookup, message_from_file, should_process_llmq_of_type, validate_llmq_callback};
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
        "27f4ddea9f4562b28ee1d01c3d66936eff7c1a7085b026bac9580e4b09000000" => 17520,
        "3ad213d512a233f2d4c0ef8763680370f1cb2edd3297701813b435e646010000" => 17544,
        "549af00509d113256ad6daa5e67573f9c79f3cd83f4c368d64651751b3040000" => 17568,
        "c410c1b60a033bb22e3da5896e4fdf825598bb72e34a8ee09205b9e162000000" => 17592,
        "ae865ff20dcf73393c1a0485099fdc638f829865577ecfe2ce4008dab7010000" => 17608,
        "09c72994f74322cb65bf2a013855198eae0de28067fd9d3bd2bb75b270020000" => 17616,
        "ffd2dc9bd11f959ee9832eddc4ef657bb2c155b66a2384853988927329040000" => 17640,
        "e7a9f187b4cadf1d1271b38431fe0a07ca094417f3683da1f775d719fa060000" => 17656,
        "7e69e2376224b50980814070ad44638cc5111e9b8ee7b887c0c0a04d58070000" => 17664,
        "558cb45c1a7c52a74f44f448fcda6e60d8357239527e937f67c45a8e1f040000" => 17688,
        "6da0b112ff140bddf9a156d0b998fa2b01d3bed2c7ba21efa7741dc719040000" => 17704,
        "9eacde48386c394570e17adf9ef90779ab321282ace87e33f7666946ed000000" => 17712,
        "44a2ea2e0cb42a9c0697fcf3a91c78d426f1db4093aa58533c8365a1d0000000" => 17736,
        "14f7db0f8ced0c907feb56a7f28965a06f7c4e67bcd0aef81c891286e7010000" => 17752,
        "d7369f81cae9a66bcc827a9870ad67242a5369a76792a4fab824442ed9050000" => 17760,
        "539ab2f275630a461f429bfffad6d9e12ccc2f25cfa57e90434b103262080000" => 17784,
        "54ecf7eb8bf41839fd544b4b8874013ed1c42c9bea5c14152e175efa3b030000" => 17800,
        "94abdfd020aaea2d655f41bb900345cc7bd1bcaef9675a4c49da6c357d040000" => 17808,
        "32d3f30cbf8d32328774ff18f49906a3383888e8296b70863aca6bc031030000" => 17822,
        "52a04d847709ce52ec88806994f49db1a7ecf9178217df97162d786ae2050000" => 17823,
        "251ad13ae41311a4515e40cd02f8586cb7305e47270ccf48e43cba3e82030000" => 17827,
        "9529062177f1500581c50bbb47f51d0bef224232a7f0871f1500406032000000" => 17829,
        "0da5c358331bbbb5015b9e83dce4e3bdc80cd80a6c25a0045e69d25dbf010000" => 17830,
        _ => u32::MAX
    }
}

#[test]
fn test_devnet_333() {
    // let bytes = message_from_file("qrinfo--1-20737.dat".to_string());
    let bytes = message_from_file("QRINFO_1_17800.dat".to_string());
    // let bytes = message_from_file("QRINFO_1_10475.dat".to_string());
    let context = &mut (FFIContext { chain: ChainType::DevNet }) as *mut _ as *mut std::ffi::c_void;
    let merkle_root = UInt256::from_hex("db682cdac4dcc62280c140d0293eec728d23cdad0c3c7774d6130984d71811a1").unwrap();
    //233e10c14601ad3e46203dae9472cb33eee4a729fbc8b7ceede956c00fbbc221
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
