use byte::{BytesExt, LE};
use dash_spv_models::common::merkle_tree::MerkleTree;
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::byte_util::{AsBytes, UInt256};
use dash_spv_primitives::crypto::data_ops::Data;
use dash_spv_primitives::hashes::hex::{FromHex, ToHex};

#[test]
fn test_multiple_merkle_hashes() {
    let merkle_hashes = Vec::from_hex("78175171f830d9ea3e67170dfdec6bd805d31b22b19eaf783355adae06faa3539762500f0eca01a59f0e198522a0752f96be9032803fb21311a992089b9472bd1361a2db43a580e40f81bd5e17eabae8eebb02e9a651ae348d88d51ca824df19").unwrap();
    let merkle_flags = Vec::from_hex("07").unwrap();
    let desired_merkle_root =
        UInt256::from_hex("bd6a344573ba1d6faf24f021324fa3360562404536246503c4cba372f94bfa4a")
            .unwrap();
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
    let merkle_tree = MerkleTree {
        tree_element_count,
        hashes: hashes.clone(),
        flags,
    };
    let has_valid_coinbase = merkle_tree.has_root(desired_merkle_root);
    println!(
        "merkle_tree: {:?} ({:?}) {:?} {}, has_valid_coinbase: {} {:?}",
        merkle_hashes.to_hex(),
        hashes.clone(),
        merkle_flags.to_hex(),
        tree_element_count,
        has_valid_coinbase,
        desired_merkle_root
    );
    assert!(has_valid_coinbase, "Invalid coinbase here");
}
#[test]
fn test_bitwise() {
    // Rust has own way...
    // objc equivalent for  UINT8_MAX >> (8 - signersOffset) << (8 - signersOffset);
    let test_values = vec![
        0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248,
        252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254,
        255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224,
        240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240,
        248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
    let bitsets: Vec<(&str, u64)> = vec![
        ("ffffffffffff03", 50),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f000000000000000000000000", 400),
        ("cff5bdfdffffff0f", 60),
        ("f7fffffffffffb0f", 60),
        ("5fffffffffffff0f", 60),
        ("5bedffffffffff0f", 60),
        ("cdffffffffdfff0f", 60),
        ("bcfffffffffffe0f", 60),
        ("fdcfffffffffff0f", 60),
        ("7bd6fffffffffd0f", 60),
        ("7fb6ffffffffff0f", 60),
        ("ffeeffffffffff0f", 60),
        ("1fcdfffffffffd0f", 60),
        ("dfbfffffffffff0f", 60),
        ("ffffffffffffff0f", 60),
        ("aff7ffffffffff0f", 60),
        ("9eceffffffffff0f", 60),
        ("fff7ffffffffff0f", 60),
        ("bfefffffffffff0f", 60),
        ("7edfffffffffff0f", 60),
        ("fefbffffffffff0f", 60),
        ("fbf7ffffffffff0b", 60),
        ("6febffffffffff0f", 60),
        ("f7ffffffffffff0d", 60),
        ("ff9fffffffffdf0f", 60),
        ("adf7ffffffffff0f", 60),
        ("9fffffffffffff0f", 60),
        ("7befffffffffff0f", 60),
        ("f3dfffffffffff0f", 60),
        ("fbffffffffffff0f", 60),
        ("bfffffffffffff0f", 60),
        ("7bfbffffff7fff0f", 60),
        ("fffeffffffdfff0f", 60),
        ("6f9fffffffffff0f", 60),
        ("fdfeffffffffff0f", 60),
    ];
    for (bitset, size) in bitsets {
        validate_bitset_new(Vec::from_hex(bitset).unwrap(), VarInt(size));
    }
}

fn validate_bitset(bitset: Vec<u8>, count: VarInt) {
    // The byte size of the signers and validMembers bitvectors must match “(quorumSize + 7) / 8”
    println!(
        "validateBitsets: {:?}:{}:{}:{}",
        bitset.to_hex(),
        bitset.len(),
        count,
        count.0 / 8
    );
    if bitset.len() != (count.0 as usize + 7) / 8 {
        assert!(false, "Error: The byte size of the signers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", bitset.len(), (count.0 + 7) / 8);
    }
    // No out-of-range bits should be set in byte representation of the signers and validMembers bitvectors
    let offset = (count.0 / 8) as i32;
    let mut s_offset = offset.clone() as usize;
    let last_byte = bitset
        .as_slice()
        .read_with::<u8>(&mut s_offset, byte::LE)
        .unwrap_or(0) as i32;

    let mask = 255 >> (((8 - offset) % 32) + 32) % 32 << (((8 - offset) % 32) + 32) % 32;
    // let mask = !(0xff >> rem);

    println!("lastByte: {} mask: {}", last_byte, mask);
    if last_byte & mask != 0 {
        println!("Error: No out-of-range bits should be set in byte representation of the signers bitvector");
        // assert!(false, "Error: No out-of-range bits should be set in byte representation of the signers bitvector");
    }
}

pub fn validate_bitset_new(bitset: Vec<u8>, count: VarInt) {
    println!(
        "validateBitsets: {:?}:{}:{}:{}",
        bitset.to_hex(),
        bitset.len(),
        count,
        count.0 / 8
    );
    assert_eq!(bitset.len(), (count.0 as usize + 7) / 8, "Error: The byte size of the signers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", bitset.len(), (count.0 + 7) / 8);
    let len = (bitset.len() * 8) as i32;
    let size = count.0 as i32;
    if len != size {
        let rem = len - size;
        let mask = !(0xff >> rem);
        let last_byte = match bitset.last() {
            Some(&last) => last as i32,
            None => 0,
        };
        println!("lastByte: {} mask: {}", last_byte, mask);
        assert_eq!(last_byte & mask, 0, "Error: No out-of-range bits should be set in byte representation of the signers bitvector");
    }
}

#[test]
pub fn test_bits_are_true_operations() {
    let number1 =
        UInt256::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let number50 =
        UInt256::from_hex("3200000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let number50_shifted =
        UInt256::from_hex("0000000000000000320000000000000000000000000000000000000000000000")
            .unwrap();
    let test_number50_shifted =
        UInt256::from_hex("0000000000000000320000000000000000000000000000000000000000000000")
            .unwrap();
    let test_number =
        UInt256::from_hex("0100000000000000320000000000000000000000000000000000000000000000")
            .unwrap();

    assert_eq!(
        number50_shifted, test_number50_shifted,
        "These numbers must be the same"
    );

    let data = test_number.as_bytes();
    assert_eq!(data.true_bits_count(), 4, "Must be 6 bits here");
    assert!(data.bit_is_true_at_le_index(0), "This must be true");
    assert!(!data.bit_is_true_at_le_index(1), "This must be false");
    assert!(data.bit_is_true_at_le_index(65), "This must be true");
    assert!(!data.bit_is_true_at_le_index(67), "This must be false");
    assert!(data.bit_is_true_at_le_index(68), "This must be true");
}
