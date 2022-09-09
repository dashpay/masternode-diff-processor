use byte::{BytesExt, LE};
use dash_spv_models::common::merkle_tree::MerkleTree;
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::byte_util::UInt256;
use dash_spv_primitives::hashes::hex::{FromHex, ToHex};

#[test]
fn test_multiple_merkle_hashes() {
    let merkle_hashes = Vec::from_hex("78175171f830d9ea3e67170dfdec6bd805d31b22b19eaf783355adae06faa3539762500f0eca01a59f0e198522a0752f96be9032803fb21311a992089b9472bd1361a2db43a580e40f81bd5e17eabae8eebb02e9a651ae348d88d51ca824df19").unwrap();
    let merkle_flags = Vec::from_hex("07").unwrap();
    let desired_merkle_root = UInt256::from_hex("bd6a344573ba1d6faf24f021324fa3360562404536246503c4cba372f94bfa4a").unwrap();
    let tree_element_count = 4;
    let flags = merkle_flags.as_slice();
    let mut hashes = Vec::<UInt256>::new();
    let hashes_count = merkle_hashes.len() / 32;
    for i in 0..hashes_count {
        let mut off = i * 32;
        if let Ok(hash) = merkle_hashes.read_with(&mut off, LE) {
            hashes.push(hash);
        }
    }
    let merkle_tree = MerkleTree { tree_element_count, hashes: hashes.clone(), flags };
    let has_valid_coinbase = merkle_tree.has_root(desired_merkle_root);
    println!("merkle_tree: {:?} ({:?}) {:?} {}, has_valid_coinbase: {} {:?}", merkle_hashes.to_hex(), hashes.clone(), merkle_flags.to_hex(), tree_element_count, has_valid_coinbase, desired_merkle_root);
    assert!(has_valid_coinbase, "Invalid coinbase here");
}
#[test]
fn test_bitwise() {
    // Rust has own way...
    // objc equivalent for  UINT8_MAX >> (8 - signersOffset) << (8 - signersOffset);
    let test_values = vec![
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut masks = vec![];
    for i in 0..416 {
        let mask = 255 >> (((8 - i) % 32) + 32) % 32 << (((8 - i) % 32) + 32) % 32;
        masks.push(mask);
    }
    assert_eq!(test_values.len(), masks.len(), "length not match");
    assert_eq!(test_values, masks, "bitwise hell");
}

#[test]
fn test_long_bitsets() {
    let bitset1 = Vec::from_hex("ffffffffffff03").unwrap();
    let count1 = VarInt(50);

    let bitset2 = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f000000000000000000000000").unwrap();
    let count2 = VarInt(400);
    let bitset3 = Vec::from_hex("fffffffffbffff0f").unwrap();
    let count3 = VarInt(60);

    //Error: No out-of-range bits should be set in byte representation of the signers bitvector: "fffffffffbffff0f" [val: 60, len: 1] 15 254 14

    validate_bitset(bitset1, count1);
    validate_bitset(bitset2, count2);
    validate_bitset(bitset3, count3);
}

fn validate_bitset(bitset: Vec<u8>, count: VarInt) {
    // The byte size of the signers and validMembers bitvectors must match “(quorumSize + 7) / 8”
    println!("validateBitsets: {:?}:{}:{}:{}", bitset.to_hex(), bitset.len(), count, count.0 / 8);
    if bitset.len() != (count.0 as usize + 7) / 8 {
        assert!(false, "Error: The byte size of the signers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", bitset.len(), (count.0 + 7) / 8);
    }
    // No out-of-range bits should be set in byte representation of the signers and validMembers bitvectors
    let offset = (count.0 / 8) as i32;
    let mut s_offset = offset.clone() as usize;
    let last_byte = bitset.as_slice().read_with::<u8>(&mut s_offset, byte::LE).unwrap_or(0) as i32;

    let mask = 255 >> (((8 - offset) % 32) + 32) % 32 << (((8 - offset) % 32) + 32) % 32;
    println!("lastByte: {} mask: {}", last_byte, mask);
    if last_byte & mask != 0 {
        assert!(false, "Error: No out-of-range bits should be set in byte representation of the signers bitvector");
    }
}

