use dash_spv_primitives::crypto::byte_util::Reversable;
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::hex::FromHex;

unsafe extern "C" fn get_merkle_root_by_hash(
    block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *const u8 {
    // 783917: 5ca438645015b048d752323557509678a5e24e9022041eba2c5b4c4419000000 -> cdd3f64e6c14268060a5332790e0034902a40438080248b4fbcee9c808cb5a5d
    let h = UInt256(*(block_hash));
    let orig_s = h.clone().to_string();
    match orig_s.as_str() {
        "5ca438645015b048d752323557509678a5e24e9022041eba2c5b4c4419000000" => {
            UInt256::from_hex("cdd3f64e6c14268060a5332790e0034902a40438080248b4fbcee9c808cb5a5d")
                .unwrap()
        }
        _ => UInt256::MIN,
    }
    .0
    .as_ptr()
}

// unsafe extern "C" fn get_block_height_by_hash(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> u32 {
//     let h = UInt256(*(block_hash));
//     let orig_s = h.clone().reversed().to_string();
//     match orig_s.as_str() {
//
//     }
//
// }

unsafe extern "C" fn get_block_hash_by_height(
    block_height: u32,
    _context: *const std::ffi::c_void,
) -> *const u8 {
    match block_height {
        5334 => {
            UInt256::from_hex("00000072f3c73d891d86546f259ba2cd87d1aa655c447640a4257f6a8e6f7018")
                .unwrap()
                .reversed()
        }
        4207 => {
            UInt256::from_hex("000000a451ba6459b3ce6128a5e8f273f9bc2010645dd4721e1b51efce18dda7")
                .unwrap()
                .reversed()
        }
        4192 => {
            UInt256::from_hex("000000076aeba26f76a5d0e12e11c9b4d35d7232f1bbae6c47b4d8bef4a12b62")
                .unwrap()
                .reversed()
        }
        4168 => {
            UInt256::from_hex("00000179987c39850ddd901eec6bfd0a508ec54fb6a0cd28481481aa0adf56b6")
                .unwrap()
                .reversed()
        }
        4144 => {
            UInt256::from_hex("00000028bd64fd360dba79acf7cb3bae6cea18553c7232894a2ace15ada70940")
                .unwrap()
                .reversed()
        }
        4120 => {
            UInt256::from_hex("000002410622902b361d1e2194f2072c6409c6f22ef5fea854d3326a27075713")
                .unwrap()
                .reversed()
        }
        4096 => {
            UInt256::from_hex("000001f340d35fe89d1924de57ccbf63a7a09347835e6e4990ee2df12a4a67f9")
                .unwrap()
                .reversed()
        }
        _ => UInt256::MIN,
    }
    .0
    .as_ptr()
}
/*
#[test]
fn testnet_backward_compatibility() {
    //MNL_0_783917
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash,
            get_block_height_by_hash,
            get_block_hash_by_height,
            get_llmq_snapshot_by_block_hash_default,
            llmq_snapshot_save_333_2,
            masternode_list_lookup_333_2,
            masternode_list_save_333_2,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            should_process_llmq_of_type_333_2,
            validate_llmq_callback,
            log_default,
        )
    };
    let cache = unsafe { processor_create_cache() };
    let context = &mut (FFIContext { chain: ChainType::TestNet, cache: MasternodeProcessorCache::default() }) as *mut _ as *mut std::ffi::c_void;

    let mnldiff_bytes = message_from_file("MNL_0_783917.dat".to_string());

    let result = process_mnlistdiff_from_message_internal(
        mnldiff_bytes.as_ptr(),
        mnldiff_bytes.len(),
        false,
        processor,
        cache,
        context
    );


    // let bytes = message_from_file("qrinfo--1-24868.dat".to_string());
    //
    // let result = process_qrinfo_from_message_internal(
    //     bytes.as_ptr(),
    //     bytes.len(),
    //     false,
    //     processor,
    //     cache,
    //     context
    // );
    // println!("Result: {:#?}", &result);
    // assert!(result.result_at_h.has_valid_mn_list_root, "Invalid masternodes root");

}
*/
