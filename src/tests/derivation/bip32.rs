use std::sync::{Arc, Mutex};
use bls_signatures::bip32::ExtendedPrivateKey;
use hashes::hex::{FromHex, ToHex};
use crate::chain::Chain;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::common::ChainType;
use crate::chain::ext::wallets::Wallets;
use crate::chain::wallet::seed::Seed;
use crate::chains_manager::ChainsManager;
use crate::derivation::BIP32_HARD;
use crate::derivation::derivation_path::DerivationPath;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::IIndexPath;
use crate::derivation::protocol::IDerivationPath;
use crate::keys::{BLSKey, ECDSAKey, IKey, KeyType};
use crate::UInt256;
use crate::util::{base58, Shared};

#[test]
fn fingerprint_for_short_bip32_seed() {
    assert_eq!(ExtendedPrivateKey::from_seed(&[1u8, 50, 6, 244, 24, 199, 1, 25])
                   .expect("cannot generate extended private key")
                   .public_key()
                   .expect("cannot get public key from extended private key")
                   .fingerprint_legacy(), 0xa4700b27);
}

#[test]
fn test_bls_fingerprint_from_seed() {
    let seed = Seed::with_data([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10].to_vec());
    assert_eq!(
        BLSKey::key_with_seed_data(&seed, true)
            .public_key_fingerprint(),
        0xddad59bb, "Testing BLS private child public key fingerprint");
    let seed = Seed::with_data([1u8, 50, 6, 244, 24, 199, 1, 25].to_vec());
    assert_eq!(BLSKey::extended_private_key_with_seed_data(&seed, true)
                .expect("Can't get extended_private_key from seed")
                .public_key_fingerprint(),
            0xa4700b27, "Testing BLS extended private child public key fingerprint");
}

#[test]
fn test_bls_derivation() {
    let chain_type = ChainType::MainNet;
    let chain = Shared::Owned(Arc::new(Mutex::new(Chain::create_mainnet())));
    let seed = Seed::with_data([1u8, 50, 6, 244, 24, 199, 1, 25].to_vec());
    let mut key_pair = BLSKey::extended_private_key_with_seed_data(&seed, true).unwrap();
    let chain_code = key_pair.chain_code;
    assert_eq!(chain_code.0.to_hex(), "d8b12555b4cc5578951e4a7c80031e22019cc0dce168b3ed88115311b8feb1e3", "Testing BLS derivation chain code");
    let derivation_path_indexes1 = vec![UInt256::from(77u64)];
    let hardened1 = vec![true];
    let derivation_path1 = DerivationPath::derivation_path_with_indexes(
        derivation_path_indexes1,
        hardened1,
        DerivationPathType::ClearFunds,
        KeyType::BLS,
        DerivationPathReference::Unknown,
        chain_type,
        chain.borrow()
    );
    let key_pair1 = key_pair.private_derive_to_path(&derivation_path1.base_index_path()).unwrap();
    let chain_code1 = key_pair1.chain_code;
    assert_eq!(chain_code1.0.to_hex(), "f2c8e4269bb3e54f8179a5c6976d92ca14c3260dd729981e9d15f53049fd698b", "Testing BLS private child derivation returning chain code");
    assert_eq!(key_pair1.public_key_fingerprint(), 0xa8063dcf, "Testing BLS extended private child public key fingerprint");

    let derivation_path_indexes2 = vec![UInt256::from(3u64), UInt256::from(17u64)];
    let hardened2 = vec![false, false];
    let derivation_path2 = DerivationPath::derivation_path_with_indexes(
        derivation_path_indexes2,
        hardened2,
        DerivationPathType::ClearFunds,
        KeyType::BLS,
        DerivationPathReference::Unknown,
        chain_type,
        chain.borrow()
    );
    let key_pair2 = key_pair.private_derive_to_path(&derivation_path2.base_index_path()).unwrap();
    assert_eq!(key_pair2.public_key_fingerprint(), 0xff26a31f, "Testing BLS extended private child public key fingerprint");
    let key_pair3 = key_pair.public_derive_to_path(&derivation_path2.base_index_path()).unwrap();
    assert_eq!(key_pair3.public_key_fingerprint(), 0xff26a31f, "Testing BLS extended private child public key fingerprint");
}

#[test]
fn test_bip32_sequence_private_key_from_string() {
    let manager = Shared::Owned(Arc::new(Mutex::new(ChainsManager::new())));
    let seed_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
    let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_phrase(seed_phrase);
    assert!(mnemonic.is_ok(), "Error parsing seed");
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let seed = Seed::with_data(seed_data);
    // let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, seed_phrase);
    manager.with(|m| m.mainnet.borrow().new_transient_wallet_with_seed_phrase::<bip0039::English>(seed_phrase).unwrap().with(|w| {
        let account = w.account_with_number(0).unwrap();
        let derivation_path = account.bip32_derivation_path.as_ref().unwrap();
        let mut pk = derivation_path.private_key_string_at_index(2 | BIP32_HARD, true, &seed).unwrap();
        let mut d = base58::from_check(pk.as_str()).unwrap();
        println!("000102030405060708090a0b0c0d0e0f/0'/1/2' prv = {}", d.to_hex());
        assert_eq!(d.to_hex(), "cccbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca01", "private_key_string_at_index");
        // Test for correct zero padding of private keys, a nasty potential bug
        pk = derivation_path.private_key_string_at_index(97, false, &seed).unwrap();
        d = base58::from_check(pk.as_str()).unwrap();
        println!("000102030405060708090a0b0c0d0e0f/0'/0/97 prv = {}", d.to_hex());
        assert_eq!(d.to_hex(), "cc00136c1ad038f9a00871895322a487ed14f1cdc4d22ad351cfa1a0d235975dd701", "private_key_string_at_index");
    }))
}

#[test]
fn test_bip32_serializations_basic() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let seed_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
    let chain = manager.mainnet.borrow();
    let wallet = chain.borrow().new_transient_wallet_with_seed_phrase::<bip0039::English>(seed_phrase).unwrap();
    //--------------------------------------------------------------------------------------------------//
    // m //
    //--------------------------------------------------------------------------------------------------//
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let seed = Seed::with_data(seed_data);
    println!("••••••••••••••••••••••••••••••••••••••");
    let indexes_root = Vec::<UInt256>::new();
    let hardened_root = Vec::<bool>::new();
    let mut root_derivation_path = DerivationPath::derivation_path_with_indexes(indexes_root, hardened_root, DerivationPathType::Unknown, KeyType::ECDSA, DerivationPathReference::Root, chain_type, chain.borrow());
    root_derivation_path.set_wallet(wallet.borrow());
    root_derivation_path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_root_extended_public_key = root_derivation_path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_root_extended_public_key, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "serialized extended public key is wrong");
    let serialized_root_extended_private_key = root_derivation_path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_root_extended_private_key, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "serialized extended private key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
    //--------------------------------------------------------------------------------------------------//
    // m/0' //
    //--------------------------------------------------------------------------------------------------//
    wallet.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let bip32_derivation_path = account.bip32_derivation_path.as_mut().unwrap();
        bip32_derivation_path.generate_extended_public_key_from_seed(&seed)
            .expect("generate_extended_public_key_from_seed");
        let serialized_bip32_extended_public_key = bip32_derivation_path.serialized_extended_public_key().unwrap();
        assert_eq!(serialized_bip32_extended_public_key, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "serialized extended public key is wrong");
        let serialized_bip32_extended_private_key = bip32_derivation_path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
        assert_eq!(serialized_bip32_extended_private_key, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "serialized extended private key is wrong");
    });
    println!("••••••••••••••••••••••••••••••••••••••");
    //--------------------------------------------------------------------------------------------------//
    // m/0'/1 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(1u64)],
        vec![true, false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "serialized extended private key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
    //--------------------------------------------------------------------------------------------------//
    // m/0'/1/2' //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(1u64), UInt256::from(2u64)],
        vec![true, false, true],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0'/1/2'/2 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(1u64), UInt256::from(2u64), UInt256::from(2u64)],
        vec![true, false, true, false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0'/1/2'/2/1000000000 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(1u64), UInt256::from(2u64), UInt256::from(2u64), UInt256::from(1000000000u64)],
        vec![true, false, true, false, false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "serialized extended private key is wrong");
}

#[test]
fn test_bip32_serializations_advanced() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let seed_data = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    let chain = manager.mainnet.borrow();
    let seed = Seed::from::<bip0039::English>(seed_data, chain_type.genesis_hash());
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());
    //--------------------------------------------------------------------------------------------------//
    // m //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![],
        vec![],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64)],
        vec![false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0/2147483647' //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(2147483647u64)],
        vec![false, true],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0/2147483647'/1 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(2147483647u64), UInt256::from(1u64)],
        vec![false, true, false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0/2147483647'/1/2147483646' //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(2147483647u64), UInt256::from(1u64), UInt256::from(2147483646u64)],
        vec![false, true, false, true],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0/2147483647'/1/2147483646'/2 //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64), UInt256::from(2147483647u64), UInt256::from(1u64), UInt256::from(2147483646u64), UInt256::from(2u64)],
        vec![false, true, false, true, false],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", "serialized extended private key is wrong");
}

#[test]
fn test_bip32_serializations_leading_zeroes() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let seed_data = Vec::from_hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
    let chain = manager.mainnet.borrow();
    let seed = Seed::from::<bip0039::English>(seed_data, chain_type.genesis_hash());
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());
    //--------------------------------------------------------------------------------------------------//
    // m //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![],
        vec![],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", "serialized extended private key is wrong");
    //--------------------------------------------------------------------------------------------------//
    // m/0' //
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64)],
        vec![true],
        DerivationPathType::Unknown,
        KeyType::ECDSA,
        DerivationPathReference::Root,
        chain_type,
        chain.borrow());
    path.set_wallet(wallet.borrow());
    path.generate_extended_public_key_from_seed_no_store(&seed);
    let serialized_extended_public_key = path.serialized_extended_public_key().unwrap();
    assert_eq!(serialized_extended_public_key, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "serialized extended public key is wrong");
    let serialized_extended_private_key = path.serialized_extended_private_key_from_seed(&seed.data).unwrap();
    assert_eq!(serialized_extended_private_key, "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "serialized extended private key is wrong");
}
#[test]
fn test_bip32_sequence_master_public_key_from_seed() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let chain = manager.mainnet.borrow();
    let seed = Seed::from::<bip0039::English>(seed_data, chain_type.genesis_hash());
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());

    wallet.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let bip32_derivation_path = account.bip32_derivation_path.as_mut().unwrap();
        bip32_derivation_path.generate_extended_public_key_from_seed(&seed)
            .expect("generate_extended_public_key_from_seed");
        let mpk = bip32_derivation_path.extended_public_key_data().unwrap();
        println!("000102030405060708090a0b0c0d0e0f/0' pub+chain = {}", mpk.to_hex());
        assert_eq!(mpk.to_hex(), "3442193e47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", "Wrong extended public key data for bip32 derivation path");
    });
}

#[test]
fn test_bip32_sequence_public_key() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let chain = manager.mainnet.borrow();
    let seed = Seed::from::<bip0039::English>(seed_data, chain_type.genesis_hash());
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());
    wallet.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let bip32_derivation_path = account.bip32_derivation_path.as_mut().unwrap();
        bip32_derivation_path.generate_extended_public_key_from_seed(&seed);
        let pubkeydata = bip32_derivation_path.public_key_data_at_index(0, false).unwrap();
        println!("000102030405060708090a0b0c0d0e0f/0'/0/0 pub = {}", pubkeydata.to_hex());
        assert_eq!(pubkeydata, Vec::from_hex("027b6a7dd645507d775215a9035be06700e1ed8c541da9351b4bd14bd50ab61428").unwrap(), "can't get external public key data at index: 0");
    });
}

#[test]
fn test_bip32_sequence_serialized_private_master_from_seed() {
    let chain_type = ChainType::MainNet;
    let seed_data = Vec::from_hex("bb22c8551ef39739fa007efc150975fce0187e675d74c804ab32f87fe0b9ad387fe9b044b8053dfb26cf9d7e4857617fa66430c880e7f4c96554b4eed8a0ad2f").unwrap();
    let xprv = ECDSAKey::serialized_private_master_key_from_seed(&seed_data, chain_type);
    println!("bb22c8551ef39739fa007efc150975fce0187e675d74c804ab32f87fe0b9ad387fe9b044b8053dfb26cf9d7e4857617fa66430c880e7f4c96554b4eed8a0ad2f xprv = {}", xprv);
    assert_eq!(xprv, "xprv9s21ZrQH143K27s8Yy6TJSKmKUxTBuXJr4RDTjJ5Jqq13d9v2VzYymSoM4VodDK7nrQHTruX6TuBsGuEVXoo91GwZnmBcTaqUhgK7HeysNv", "not as expected");
}

#[test]
fn test_bip32_sequence_serialized_master_public_key() {
    // stay issue box trade stock chaos raccoon candy obey wet refuse carbon silent guide crystal
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let chain = manager.mainnet.borrow();
    let seed_data = Vec::from_hex("bb22c8551ef39739fa007efc150975fce0187e675d74c804ab32f87fe0b9ad387fe9b044b8053dfb26cf9d7e4857617fa66430c880e7f4c96554b4eed8a0ad2f").unwrap();
    let seed = Seed::from::<bip0039::English>(seed_data, chain_type.genesis_hash());
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());
    wallet.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let path = account.bip32_derivation_path.as_mut().unwrap();
        path.generate_extended_public_key_from_seed(&seed);
        let xpub = path.serialized_extended_public_key().unwrap();
        println!("bb22c8551ef39739fa007efc150975fce0187e675d74c804ab32f87fe0b9ad387fe9b044b8053dfb26cf9d7e4857617fa66430c880e7f4c96554b4eed8a0ad2f xpub = {}", xpub);
        assert_eq!(xpub, "xpub6949NHhpyXW7qCtj5eKxLG14JgbFdxUwRdmZ4M51t2Bcj95bCREEDmvdWhC6c31SbobAf5X86SLg76A5WirhTYFCG5F9wkeY6314q4ZtA68", "wrong serialized extended public key");
    });


    let seed_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
    let seed = Seed::from_phrase::<bip0039::English>(seed_phrase, chain_type.genesis_hash()).unwrap();
    assert_eq!(seed.data.to_hex(), "467c2dd58bbd29427fb3c5467eee339021a87b21309eeabfe9459d31eeb6eba9b2a1213c12a173118c84fd49e8b4bf9282272d67bf7b7b394b088eab53b438bc", "wrong key derived from phrase");
    let wallet2 = chain.borrow().new_transient_wallet_with_seed_phrase::<bip0039::English>(seed_phrase).unwrap();
    wallet2.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let path = account.bip32_derivation_path.as_mut().unwrap();
        path.generate_extended_public_key_from_seed(&seed);
        let mpk = path.extended_public_key_data().unwrap();
        assert_eq!(mpk.to_hex(), "c93fa1867e984d7255df4736e7d7d6243026b9744e62374cbb54a0a47cc0fe0c334f876e02cdfeed62990ac98b6932e0080ce2155b4f5c7a8341271e9ee9c90cd87300009c", "extended public key data is wrong");
        let xpub = path.serialized_extended_public_key().unwrap();
        assert_eq!(xpub, "xpub69NHuRQrRn5GbT7j881uR64arreu3TFmmPAMnTeHdGd68BmAFxssxhzhmyvQoL3svMWTSbymV5FdHoypDDmaqV1C5pvnKbcse1vgrENbau7", "serialized extended public key is wrong");
    });
}

#[test]
fn test_bip44_sequence_serialized_master_public_key() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    let chain = manager.mainnet.borrow();
    let seed_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
    let seed = Seed::from_phrase::<bip0039::English>(seed_phrase, chain_type.genesis_hash()).unwrap();
    let wallet = chain.borrow().transient_wallet_with_seed::<bip0039::English>(seed.clone());
    wallet.with(|w| {
        let account = w.account_with_number_mut(0).unwrap();
        let path = account.bip44_derivation_path.as_mut().unwrap();
        path.generate_extended_public_key_from_seed(&seed);
        let mpk = path.extended_public_key_data().unwrap();
        assert_eq!(mpk.to_hex(), "4687e396a07188bd71458a0e90987f92b18a6451e99eb52f0060be450e0b4b3ce3e49f9f033914476cf503c7c2dcf5a0f90d3e943a84e507551bdf84891dd38c0817cca97a", "wrong bip44 extended public key data");
        let xpub = path.serialized_extended_public_key().unwrap();
        assert_eq!(xpub, "xpub6CAqVZYbGiQCTyzzvvueEoBy8M74VWtPywf2F3zpwbS8AugDSSMSLcewpDaRQxVCxtL4kbTbWb1fzWg2R5933ECsxrEtKBA4gkJu8quduHs", "wrong serialized bip44 extended public key");
        let de_mpk = DerivationPath::deserialized_extended_private_key_for_chain(&xpub, chain_type).unwrap();
        assert_eq!(mpk.to_hex(), de_mpk.to_hex(), "wrong deserialized extended private key for chain");
    });
}

