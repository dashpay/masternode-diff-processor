use base64::{alphabet, Engine};
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use bls_signatures::{PrivateKey, G1Element};
use byte::BytesExt;
use hashes::hex::{FromHex, ToHex};
use hashes::{Hash, sha256d};
use crate::chain::ScriptMap;
use crate::chain::wallet::seed::Seed;
use crate::keys::{BLSKey, CryptoData, IKey};
use crate::UInt256;
use crate::util::Address;

#[test]
pub fn test_bls_sign() {
    // In dash we use SHA256_2, however these test vectors from the BLS library use a single SHA256
    let seed1 = Seed::with_data([1u8,2,3,4,5].to_vec());
    let seed2 = Seed::with_data([1u8,2,3,4,5,6].to_vec());
    let keypair1 = BLSKey::key_with_seed_data(&seed1.data, true);
    let keypair2 = BLSKey::key_with_seed_data(&seed2.data, true);
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
    assert_eq!(keypair1.secret_key.0.to_hex(), "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e", "Testing BLS private key");
    let signature2 = keypair2.sign_data_single_sha256(&message1);
    assert_eq!(signature2.0.to_hex(), "975b5daa64b915be19b5ac6d47bc1c2fc832d2fb8ca3e95c4805d8216f95cf2bdbb36cc23645f52040e381550727db420b523b57d494959e0e8c0c6060c46cf173872897f14d43b2ac2aec52fc7b46c02c5699ff7a10beba24d3ced4e89c821e", "Testing BLS signing");
}

#[test]
fn test_bls_verify() {
    let seed1 = Seed::with_data([1u8,2,3,4,5].to_vec());
    let message1: Vec<u8> = vec![7, 8, 9];
    let mut key_pair1 = BLSKey::key_with_seed_data(&seed1.data, true);
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
fn test_bls_encryption_and_decryption() {
    let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
    let alice_seed = Seed::with_data([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10].to_vec());
    let alice_key_pair = BLSKey::key_with_seed_data(&alice_seed.data, true);
    let alice_public_key_data = alice_key_pair.public_key_data();
    let alice_private_key_data = alice_key_pair.private_key_data().unwrap();
    let alice_public_key_data_base64 = base64_engine.encode(&alice_public_key_data);
    let alice_private_key_data_base64 = base64_engine.encode(&alice_private_key_data);
    let alice_test_public_key_data = Vec::from_hex("1790635de8740e9a6a6b15fb6b72f3a16afa0973d971979b6ba54761d6e2502c50db76f4d26143f05459a42cfd520d44").unwrap();
    let alice_test_private_key_data = Vec::from_hex("46891c2cec49593c81921e473db7480029e0fc1eb933c6b93d81f5370eb19fbd").unwrap();
    let alice_test_public_key_data_base64_str = "F5BjXeh0DppqaxX7a3LzoWr6CXPZcZeba6VHYdbiUCxQ23b00mFD8FRZpCz9Ug1E";
    let alice_test_private_key_data_base64_str = "RokcLOxJWTyBkh5HPbdIACng/B65M8a5PYH1Nw6xn70=";
    let alice_address = Address::with_public_key_data(&alice_public_key_data, &ScriptMap::TESTNET);
    let alice_test_address = "yi4HkZyrJQTKRD6p6p6Akiq7d1j1uBMYFP";
    assert_eq!(alice_private_key_data, alice_test_private_key_data, "BLS privateKeyData is incorrect");
    assert_eq!(alice_private_key_data_base64.as_str(), alice_test_private_key_data_base64_str, "BLS privateKeyData is incorrect");
    assert_eq!(alice_public_key_data, alice_test_public_key_data, "BLS publicKeyData is incorrect");
    assert_eq!(alice_public_key_data_base64.as_str(), alice_test_public_key_data_base64_str, "BLS publicKeyData is incorrect");
    assert_eq!(alice_address.as_str(), alice_test_address, "BLS Address::with_public_key_data for testnet is incorrect");

    let bob_seed = Seed::with_data([10u8, 9, 8, 7, 6, 6, 7, 8, 9, 10].to_vec());
    let bob_key_pair = BLSKey::key_with_seed_data(&bob_seed.data, true);
    let bob_public_key_data = bob_key_pair.public_key_data();
    let bob_private_key_data = bob_key_pair.private_key_data().unwrap();
    assert_eq!(bob_public_key_data, Vec::from_hex("0e2f9055c17eb13221d8b41833468ab49f7d4e874ddf4b217f5126392a608fd48ccab3510548f1da4f397c1ad4f8e01a").unwrap(), "BLS publicKeyData is incorrect");
    assert_eq!(base64_engine.encode(&bob_public_key_data).as_str(), "Di+QVcF+sTIh2LQYM0aKtJ99TodN30shf1EmOSpgj9SMyrNRBUjx2k85fBrU+OAa", "BLS publicKeyData is incorrect");
    assert_eq!(bob_private_key_data, Vec::from_hex("2513a9d824e763f8b3ff4304c5d52d05154a82b4c975da965f124e5dcf915805").unwrap(), "BLS privateKeyData is incorrect");
    assert_eq!(base64_engine.encode(&bob_private_key_data).as_str(), "JROp2CTnY/iz/0MExdUtBRVKgrTJddqWXxJOXc+RWAU=", "BLS privateKeyData is incorrect");
    assert_eq!(Address::with_public_key_data(&bob_public_key_data, &ScriptMap::TESTNET), "yMfTGcBjCLxyefxAdSSyFnSYgU6cJzmrs2", "BLS Address::with_public_key_data for testnet is incorrect");
    let secret = "my little secret is a pony that never sleeps";
    // Alice is sending to Bob
    let mut secret_data = secret.as_bytes().to_vec();
    let iv = Vec::from_hex("eac5bcd6eb85074759e0261497428c9b").unwrap();
    // for non-CTR
    // let test_encrypted_data = Vec::from_hex("eac5bcd6eb85074759e0261497428c9bd72bd418ce96e69cbb6766e59f8d1f8138afb0686018bb4d401369e77ba47367f93a49a528f4cc9e3f209a515e6dd8f2").unwrap();
    let test_encrypted_data = Vec::from_hex("eac5bcd6eb85074759e0261497428c9b32aafca348ab87e2744258de7e4ee3dc236da891c4feeb34cf3b20ddf6d35d526bc4e6b456f3623811e3534f").unwrap();
    match secret_data.encrypt_with_secret_key_using_iv(&alice_key_pair, &bob_key_pair, iv) {
        Some(mut encrypted_data) => {
            assert_eq!(encrypted_data, test_encrypted_data);
            // Bob is receiving from Alice
            assert_eq!(secret, String::from_utf8(
                encrypted_data.decrypt_with_secret_key(&bob_key_pair, &alice_key_pair)
                    .expect("No data decrypted"))
                .expect("Non-utf8 bytes").as_str(),
                       "they should be the same string");
        },
        None => panic!("No data encrypted"),
    };
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
