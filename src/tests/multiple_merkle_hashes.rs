use byte::{BytesExt, LE};
use dash_spv_models::common::merkle_tree::MerkleTree;
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
