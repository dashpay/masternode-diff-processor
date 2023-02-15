use std::collections::BTreeMap;
use std::ptr::null_mut;
use hashes::hex::FromHex;
use crate::common::chain_type::DevnetType;
use crate::common::ChainType;
use crate::{boxed, models, process_mnlistdiff_from_message, processor_create_cache, register_processor, ToFFI, types, UInt256};
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, FFIContext, get_llmq_snapshot_by_block_hash_default, hash_destroy_default, log_default, masternode_list_destroy_default, masternode_list_save_in_cache, MerkleBlock, message_from_file, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, snapshot_destroy_default};
use crate::tests::llmq_rotation::validate_llmq_callback_throuh_rust_bls;

unsafe extern "C" fn get_merkle_root_for_chacha(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    let h = UInt256(*(block_hash));
    // for block_hash '9993903c63b96f9a3846692535a11da2525561f0d61c7d31b7222bfddf020000':
    let merkle_root =
        UInt256::from_hex("42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e")
            .unwrap();
    println!("get_merkle_root_for_chacha: {}: {}", h, merkle_root);
    boxed(merkle_root.0) as *mut _
}

unsafe extern "C" fn get_block_height_by_hash_chacha(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> u32 {
    let h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    match orig_s.as_str() {
        "8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220" => 1,
        "3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000" => 9192,
        "9993903c63b96f9a3846692535a11da2525561f0d61c7d31b7222bfddf020000" => 9247,
        _ => u32::MAX,
    }
}
unsafe extern "C" fn get_block_hash_by_height_chacha(
    block_height: u32,
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    match block_height {
        9192 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        9184 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        9160 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        9136 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        9120 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        // 9112 => boxed(UInt256::from_hex("3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000").unwrap().0) as *mut _,
        _ => null_mut()
    }
}


pub unsafe extern "C" fn should_process_llmq_of_type_chacha(
    llmq_type: u8,
    context: *const std::ffi::c_void,
) -> bool {
    llmq_type == 101
    //println!("should_process_llmq_of_type_chacha: {}", llmq_type);
    //true
}

pub unsafe extern "C" fn get_masternode_list_at_9192(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut types::MasternodeList {
    let h = UInt256(*(block_hash));
    let nodes = BTreeMap::new();
    let quorums = BTreeMap::new();
    let list = models::MasternodeList::new(nodes, quorums, h, 9192, true);
    let encoded = list.encode();
    boxed(encoded)
}


#[test]
fn test_basic_bls_scheme() {
    let chain = ChainType::DevNet(DevnetType::Chacha);
    let genesis =
        UInt256::from_hex("8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220")
            .unwrap();
    let processor = unsafe {
        register_processor(
            get_merkle_root_for_chacha,
            get_block_height_by_hash_chacha,
            get_block_hash_by_height_chacha,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_in_cache,
            get_masternode_list_at_9192,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type_chacha,
            validate_llmq_callback_throuh_rust_bls,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: vec![]
    }) as *mut _ as *mut std::ffi::c_void;
    let bytes = message_from_file("MNL_1_9247.dat".to_string());
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        false,
        true,
        70225,
        genesis.0.as_ptr(),
        processor,
        cache,
        context,
    )};
    println!("Result: {:#?}", &result);
}

unsafe extern "C" fn get_merkle_root_for_mojito(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    let h = UInt256(*(block_hash));
    // 720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000 -> f0597c739df147363e06988fb4132dde4fbc66418b28a4e5d74e552ad2d555d0
    let merkle_root = UInt256::from_hex("f0597c739df147363e06988fb4132dde4fbc66418b28a4e5d74e552ad2d555d0")
            .unwrap();
    println!("get_merkle_root_for_mojito: {}: {}", h, merkle_root);
    boxed(merkle_root.0) as *mut _
}
unsafe extern "C" fn get_block_height_by_hash_mojito(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> u32 {
    let h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    match orig_s.as_str() {
        "739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357" => 1,
        "720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000" => 4450,
        _ => u32::MAX,
    }
}
unsafe extern "C" fn get_block_hash_by_height_mojito(
    block_height: u32,
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    match block_height {
        1 => boxed(UInt256::from_hex("739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357").unwrap().0) as *mut _,
        4450 => boxed(UInt256::from_hex("720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000").unwrap().0) as *mut _,
        _ => null_mut()
    }
}
pub unsafe extern "C" fn get_masternode_list_mojito(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut types::MasternodeList {
    null_mut()
    // let h = UInt256(*(block_hash));
    // let nodes = BTreeMap::new();
    // let quorums = BTreeMap::new();
    // let list = models::MasternodeList::new(nodes, quorums, h, 9192, true);
    // let encoded = list.encode();
    // boxed(encoded)
}
pub unsafe extern "C" fn should_process_llmq_of_type_mojito(
    llmq_type: u8,
    context: *const std::ffi::c_void,
) -> bool {
    llmq_type == 101
    //println!("should_process_llmq_of_type_chacha: {}", llmq_type);
    //true
}

#[test]
fn test_dip_0027() {
    let chain = ChainType::DevNet(DevnetType::Mojito);
    let genesis =
        UInt256::from_hex("739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357")
            .unwrap();
    let processor = unsafe {
        register_processor(
            get_merkle_root_for_mojito,
            get_block_height_by_hash_mojito,
            get_block_hash_by_height_mojito,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_in_cache,
            get_masternode_list_mojito,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type_mojito,
            validate_llmq_callback_throuh_rust_bls,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: vec![
            MerkleBlock { hash: UInt256::from_hex("739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357").unwrap(), height: 1, merkleroot: Default::default() },
            MerkleBlock { hash: UInt256::from_hex("720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000").unwrap(), height: 4450, merkleroot: UInt256::from_hex("f0597c739df147363e06988fb4132dde4fbc66418b28a4e5d74e552ad2d555d0")
                .unwrap() }
        ]
    });
    let bytes = message_from_file("MNL_1_4450.dat".to_string());
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        false,
        true,
        70226,
        genesis.0.as_ptr(),
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    let result = unsafe { *result };
    println!("Result: {:#?}", &result);
    assert_diff_result(context, result);
}

unsafe extern "C" fn get_merkle_root_for_white_russian(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    let h = UInt256(*(block_hash));
    // 720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000 -> f0597c739df147363e06988fb4132dde4fbc66418b28a4e5d74e552ad2d555d0
    let merkle_root = UInt256::from_hex("f0597c739df147363e06988fb4132dde4fbc66418b28a4e5d74e552ad2d555d0")
        .unwrap();
    println!("get_merkle_root_for_white_russian: {}: {}", h, merkle_root);
    boxed(merkle_root.0) as *mut _
}

pub unsafe extern "C" fn should_process_llmq_of_type_white_russian(
    llmq_type: u8,
    context: *const std::ffi::c_void,
) -> bool {
    llmq_type == 106
    //println!("should_process_llmq_of_type_chacha: {}", llmq_type);
    //true
}
unsafe extern "C" fn get_block_height_by_hash_white_russian(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> u32 {
    let h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    match orig_s.as_str() {
        "739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357" => 1,
        "720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000" => 4450,
        _ => u32::MAX,
    }
}
unsafe extern "C" fn get_block_hash_by_height_white_russian(
    block_height: u32,
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    match block_height {
        1 => boxed(UInt256::from_hex("739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357").unwrap().0) as *mut _,
        4450 => boxed(UInt256::from_hex("720ea2e4e7f6b31debe9bb852e1e4cdfdf10bed9827f0ef6527cfa0261010000").unwrap().0) as *mut _,
        _ => null_mut()
    }
}

#[test]
fn test_core19_beta5() {
    let chain = ChainType::DevNet(DevnetType::WhiteRussian);
    let genesis =
        UInt256::from_hex("5eca658095d6639161ce74240f6fc373ba5c5f210c26468835cb853500d03b63")
            .unwrap();
    let processor = unsafe {
        register_processor(
            get_merkle_root_for_white_russian,
            get_block_height_by_hash_white_russian,
            get_block_hash_by_height_white_russian,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_in_cache,
            get_masternode_list_mojito,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type_white_russian,
            validate_llmq_callback_throuh_rust_bls,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            log_default,
        )
    };
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: vec![
            MerkleBlock::new(1, "9163d6958065ca5e73c36f0f2474ce618846260c215f5cba633bd0003585cb35", ""),
            MerkleBlock::new(4290, "64287dd971d99adb10efdfb61097ba0fa651deda3886f3dd8e258e7364000000", ""),
        ]
    });
    let bytes = message_from_file("MNL_WHITE_RUSSIAN_1_4290.dat".to_string());
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        false,
        true,
        70227,
        genesis.0.as_ptr(),
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    let result = unsafe { *result };
    println!("Result: {:#?}", &result);
    assert_diff_result(context, result);
}
