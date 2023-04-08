use hashes::hex::FromHex;
use hashes::{sha256, Hash};

use crate::chain::common::ChainType;
use crate::crypto::UInt256;
use crate::keys::{ECDSAKey, IKey};
use crate::util::address::address::is_valid_dash_private_key;
use crate::util::base58;

// TODO: impl bip38 and their tests

fn test_sign_key(secret: &str, message: &str, compressed: bool, test_signature: &str) {
    match ECDSAKey::key_with_secret_hex(secret, compressed) {
        Some(mut key) => {
            let message_digest = sha256::Hash::hash(message.as_bytes()).into_inner().to_vec();
            let sig = key.sign(&message_digest);
            let test_sig = Vec::from_hex(test_signature).unwrap();
            assert_eq!(sig, test_sig, "Signature don't match");
            assert!(key.verify(&message_digest, &sig), "Can't verify signature");
        },
        None => panic!("key_with_secret_hex: Key is invalid"),
    }
}

fn test_compact_signature_recovery(signature: &[u8], md: UInt256, test_data: Vec<u8>) {
    match ECDSAKey::key_with_compact_sig(signature, md) {
        Some(key) => assert_eq!(key.public_key_data(), test_data, "public key data doesn't match"),
        _ => panic!("Key can't recovered")
    }
}

fn test_compact_signature_key(secret: &str, message: &str, compressed: bool) {
    match ECDSAKey::key_with_secret_hex(secret, compressed) {
        Some(key) => {
            let message_digest = UInt256::sha256_str(message);
            let sig = key.compact_sign(message_digest);
            test_compact_signature_recovery(&sig, message_digest, key.public_key_data());
        },
        None => panic!("key_with_secret_hex: Key is invalid")
    }
}

fn test_restore_compact_signatures_from_base58(signature: &str, message: &str, test_key: &str) {
    match (base58::from(signature),
           base58::from(test_key)) {
        (Ok(sig), Ok(data)) => test_compact_signature_recovery(&sig, UInt256::sha256d_str(message), data),
        _ => panic!("Bad base58")
    }
}

#[test]
pub fn test_key_with_private_key() {
    let chain_type = ChainType::MainNet;
    // wrong private key
    assert!(!is_valid_dash_private_key("7s18Ypj1scza76SPf56Jm9zraxSrv58TgzmxwuDXoauvV84ud61", &chain_type.script_map()), "valid when invalid");
    assert!(ECDSAKey::key_with_private_key("hello", chain_type).is_none(), "valid when totally invalid");
    // uncompressed private key
    assert!(is_valid_dash_private_key("7r17Ypj1scza76SPf56Jm9zraxSrv58ThzmxwuDXoauvV84ud62", &chain_type.script_map()), "invalid when valid");
    match ECDSAKey::key_with_private_key("7r17Ypj1scza76SPf56Jm9zraxSrv58ThzmxwuDXoauvV84ud62", chain_type) {
        Some(key) => {
            let addr = key.address_with_public_key_data(&chain_type.script_map());
            assert_eq!("Xj74g7h8pZTzqudPSzVEL7dFxNZY95Emcy", addr.as_str(), "addresses don't match");
        },
        None => { assert!(false, "Key is invalid"); }
    }

    // compressed private key
    match ECDSAKey::key_with_private_key("XDHVuTeSrRs77u15134RPtiMrsj9KFDvsx1TwKUJxcgb4oiP6gA6", chain_type) {
        Some(key) => {
            let addr = key.address_with_public_key_data(&chain_type.script_map());
            assert_eq!("XbKPGyV1BpzzxNAggx6Q9a6o7GaBWTLhJS", addr.as_str(), "addresses don't match");
            // compressed private key export
            assert_eq!("XDHVuTeSrRs77u15134RPtiMrsj9KFDvsx1TwKUJxcgb4oiP6gA6", key.serialized_private_key_for_script(&chain_type.script_map()).as_str(), "serialized_private_key_for_script");
        },
        None => { assert!(false, "Key is invalid"); }
    };
}

#[test]
pub fn test_sign() {
    test_sign_key(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "Everything should be made as simple as possible, but not simpler.",
        true,
        "3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
    );
    test_sign_key(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "Equations are more important to me, because politics is for the present, but an equation is something for eternity.",
        true,
        "3044022054c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed022007082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5"
    );
    test_sign_key(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "Not only is the Universe stranger than we think, it is stranger than we can think.",
        true,
        "3045022100ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd002206fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283"
    );
    test_sign_key(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "How wonderful that we have met with a paradox. Now we have some hope of making progress.",
        true,
        "3045022100c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d3022075afdc06b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3"
    );
    test_sign_key(
        "69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64",
        "Computer science is no more about computers than astronomy is about telescopes.",
        true,
        "304402207186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d02200de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6"
    );
    test_sign_key(
        "00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637",
        "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough",
        true,
        "3045022100fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda48702200e68880ebb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37"
    );
    test_sign_key(
        "000000000000000000000000000000000000000000056916d0f9b31dc9b637f3",
        "The question of whether computers can think is like the question of whether submarines can swim.",
        true,
        "3045022100cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf9022006ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef"
    );
}

#[test]
fn test_compact_sign() {
    let secret = "0000000000000000000000000000000000000000000000000000000000000001";
    test_compact_signature_key(secret, "foo", true);
    test_compact_signature_key(secret, "foo", false);
    test_restore_compact_signatures_from_base58(
        "3kq9e842BzkMfbPSbhKVwGZgspDSkz4YfqjdBYQPWDzqd77gPgR1zq4XG7KtAL5DZTcfFFs2iph4urNyXeBkXsEYY",
        "i am a test signed string",
        "26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG");
    test_restore_compact_signatures_from_base58(
        "3qECEYmb6x4X22sH98Aer68SdfrLwtqvb5Ncv7EqKmzbxeYYJ1hU9irP6R5PeCctCPYo5KQiWFgoJ3H5MkuX18gHu",
        "i am a test signed string do de dah",
        "26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG");

    test_restore_compact_signatures_from_base58(
        "3oHQhxq5eW8dnp7DquTCbA5tECoNx7ubyiubw4kiFm7wXJF916SZVykFzb8rB1K6dEu7mLspBWbBEJyYk79jAosVR",
        "i am a test signed string",
        "gpRv1sNA3XURB6QEtGrx6Q18DZ5cSgUSDQKX4yYypxpW");
}

/*#[test]
fn test_ecdsa_encryption_and_decryption() {
    let alice_secret = "0000000000000000000000000000000000000000000000000000000000000001";
    let alice_key_pair = ECDSAKey::key_with_secret_hex(alice_secret, true).unwrap();
    let bob_secret = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
    let mut bob_key_pair = ECDSAKey::key_with_secret_hex(bob_secret, true).unwrap();
    let secret = "my little secret is a pony that never sleeps";
    let key = ECDSAKey::init_with_dh_key_exchange_with_public_key(&mut bob_key_pair, &alice_key_pair).unwrap();
    assert_eq!(key.public_key_data().to_hex(), "fbd27dbb9e7f471bf3de3704a35e884e37d35c676dc2cc8c3cc574c3962376d2", "they should be the same data");
    // Alice is sending to Bob
    let mut secret_data = secret.as_bytes().to_vec();
    match secret_data.encrypt_with_secret_key_using_iv(&alice_key_pair, &bob_key_pair, Vec::from_hex("eac5bcd6eb85074759e0261497428c9b").unwrap()) {
        Some(mut encrypted_data) => {
            // assert_eq!(encrypted_data.to_hex(), "eac5bcd6eb85074759e0261497428c9b3725d3b9ec4d739a842116277c6ace81549089be0d11a54ee09a99dcf7ac695a8ea56d41bf0b62def90b6f78f8b0aca9", "they should be the same data");
            assert_eq!(encrypted_data.to_hex(), "eac5bcd6eb85074759e0261497428c9bf252dfbc0d136041c3fd7223294dabf58256588d60e11d599fcc3c9295eb9f7163adcc8f1a1bc9f01f782a01", "they should be the same data");
            // Bob is receiving from Alice
            match encrypted_data.decrypt_with_secret_key(&bob_key_pair, &alice_key_pair) {
                Some(decrypted_data) => {
                    match String::from_utf8(decrypted_data) {
                        Ok(decrypted_secret) => assert_eq!(secret, decrypted_secret.as_str(), "they should be the same string"),
                        Err(err) => panic!("Non-utf8 bytes")
                    }
                },
                None => panic!("No data decrypted"),
            }
        },
        None => panic!("No data encrypted"),
    }
}*/
