use bls_signatures::{PrivateKey, G1Element};
use byte::BytesExt;
use hashes::hex::{FromHex, ToHex};
use hashes::{Hash, sha256d};
use crate::keys::{BLSKey, IKey};
use crate::UInt256;

#[test]
pub fn test_bls_sign() {
    // In dash we use SHA256_2, however these test vectors from the BLS library use a single SHA256
    let seed1 = vec![1u8,2,3,4,5];
    let seed2 = vec![1u8,2,3,4,5,6];
    let keypair1 = BLSKey::key_with_seed_data(&seed1, true);
    let keypair2 = BLSKey::key_with_seed_data(&seed2, true);
    let message1: Vec<u8> = vec![7,8,9];
    let message2: Vec<u8> = vec![1,2,3];
    let message3: Vec<u8> = vec![1,2,3,4];
    let message4: Vec<u8> = vec![1,2];
    let fingerprint1 = keypair1.public_key_fingerprint();
    let fingerprint2 = keypair2.public_key_fingerprint();
    assert_eq!(fingerprint1, 0x26d53247, "Testing BLS private child public key fingerprint");
    assert_eq!(fingerprint2, 0x289bb56e, "Testing BLS private child public key fingerprint");
    let signature1 = keypair1.sign_data_single_sha256(&message1);
    assert_eq!(signature1.0.to_hex(), "93eb2e1cb5efcfb31f2c08b235e8203a67265bc6a13d9f0ab77727293b74a357ff0459ac210dc851fcb8a60cb7d393a419915cfcf83908ddbeac32039aaa3e8fea82efcb3ba4f740f20c76df5e97109b57370ae32d9b70d256a98942e5806065", "Testing BLS signing");
    assert_eq!(keypair1.seckey.0.to_hex(), "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e", "Testing BLS private key");
    let signature2 = keypair2.sign_data_single_sha256(&message1);
    assert_eq!(signature2.0.to_hex(), "975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdbb36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf173872897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e", "Testing BLS signing");
}

#[test]
fn test_bls_verify() {
    let seed1 = vec![1u8,2,3,4,5];
    let message1: Vec<u8> = vec![7, 8, 9];
    let mut key_pair1 = BLSKey::key_with_seed_data(&seed1, true);
    assert_eq!(key_pair1.public_key_data().to_hex(), "02a8d2aaa6a5e2e08d4b8d406aaf0121a2fc2088ed12431e6b0663028da9ac5922c9ea91cde7dd74b7d795580acc7a61");
    assert_eq!(key_pair1.private_key_data().unwrap().to_hex(), "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e");
    let signature1 = key_pair1.sign_data(&message1);
    assert_eq!(signature1.0.to_hex(), "023f5c750f402c69dab304e5042a7419722536a38d58ce46ba045be23e99d4f9ceeffbbc6796ebbdab6e9813c411c78f07167a3b76bef2262775a1e9f95ff1a80c5fa9fe8daa220d4d9da049a96e8932d5071aaf48fbff27a920bc4aa7511fd4");
    assert!(key_pair1.verify(&sha256d::Hash::hash(&message1).into_inner().to_vec(), &signature1.0.to_vec()), "Testing BLS signature verification");
}

#[test]
fn test_bls_multiplication() {
    let private_key_data = Vec::from_hex("46891c2cec49593c81921e473db7480029e0fc1eb933c6b93d81f5370eb19fbd").unwrap();
    let public_key_data = Vec::from_hex("0e2f9055c17eb13221d8b41833468ab49f7d4e874ddf4b217f5126392a608fd48ccab3510548f1da4f397c1ad4f8e01a").unwrap();
    let expected_data = UInt256::from_hex("03fd387c4d4c66ec9dcdb31ef0c08ad881090dcda13d4b2c9cbc5ef264ff4dc7").unwrap();
    println!("private_key: {:?}", private_key_data.as_slice());
    println!("public_key: {:?}", public_key_data.as_slice());
    println!("expected_data: {:?}", expected_data.0);
    let private_key = PrivateKey::from_bytes(&private_key_data, false).unwrap();
    let public_key = G1Element::from_bytes_legacy(&public_key_data).unwrap();
    let result = private_key * public_key;
    let result_serialize = result.unwrap().serialize_legacy().read_with::<UInt256>(&mut 0, byte::LE).unwrap();
    assert_eq!(result_serialize, expected_data);
}

#[test]
fn test_bls_from_bip32_short_seed() {
    let private_key = PrivateKey::from_bip32_seed(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    println!("{:?}", &*private_key.serialize());
    println!("{:?}", &*private_key.serialize().as_slice());
    assert_eq!(
        private_key.serialize().as_slice(),
        Vec::from_hex("46891c2cec49593c81921e473db7480029e0fc1eb933c6b93d81f5370eb19fbd").unwrap().as_slice(),
        "----");
}

#[test]
fn test_bls_from_bip32_long_seed() {
    let seed = Vec::from_hex("0102030405060708090a0102030405060708090a0102030405060708090a0102").unwrap();
    let private_key_test_data = Vec::from_hex("32439470cf06d276897d1b9069bdd6e4445390cd506985de0e1a1c88a76ff176").unwrap();
    println!("{:?}", seed);
    println!("{:?}", private_key_test_data);
    // let seed = [50, 67, 148, 112, 207, 6, 210, 118, 137, 125, 27, 144, 105, 189, 214, 228, 68, 83, 144, 205, 80, 105, 133, 222, 14, 26, 28, 136, 167, 111, 241, 118];
    // let secret =
    let private_key = PrivateKey::from_bip32_seed(&seed);
    println!("{:?}", &*private_key.serialize());
    println!("{:?}", &*private_key.serialize().as_slice());
    assert_eq!(
        private_key.serialize().as_slice(),
        private_key_test_data.as_slice(),
        "----");

}
