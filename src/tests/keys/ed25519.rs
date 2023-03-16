use std::sync::Weak;
use hashes::hex::{FromHex, ToHex};
use crate::chain::common::ChainType;
use crate::chain::ext::wallets::WalletCreation;
use crate::chain::wallet::seed::Seed;
use crate::chains_manager::ChainsManager;
use crate::crypto::{ECPoint, UInt512};
use crate::derivation::{DerivationPath, DerivationPathReference, DerivationPathType, IDerivationPath};
use crate::keys::{IKey, KeyType};
use crate::UInt256;

// Test vectors taken from  https://github.com/satoshilabs/slips/blob/master/slip-0010.md
#[test]
pub fn test_key_with_private_key() {
    let seed_data = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    //--------------------------------------------------------------------------------------------------//
    // m //
    // fingerprint: 00000000
    // chain code: ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b
    // private: 171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012
    // public: 008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a
    //--------------------------------------------------------------------------------------------------//
    let i = UInt512::ed25519_seed_key(&seed_data);
    let seckey = ed25519_dalek::SecretKey::try_from(&i.0[..32]).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seckey);
    let public_key = ECPoint::from(ed25519_dalek::VerifyingKey::from(&signing_key));
    let chaincode = UInt256::from(&i.0[32..]);
    assert_eq!(signing_key.to_bytes().to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    assert_eq!(public_key.0.to_hex(), "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
}

#[test]
pub fn test_vector_1_derivation() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    // let mut chain = ;
    // Test Vector 1
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    manager.mainnet.wallet_with_seed(Seed::with_data(seed_data.clone()), false, chain_type);
    let chain = manager.mainnet.read().unwrap();
    let wallet = chain.wallets.first().unwrap();
    //--------------------------------------------------------------------------------------------------//
    // Chain m
    // • fingerprint: 00000000
    // • chain code: 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
    // • private: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
    // • public: 00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed
    //--------------------------------------------------------------------------------------------------//
    println!("••••••••••••••••••••••••••••••••••••••");
    let indexes_root = Vec::<UInt256>::new();
    let hardened_root = Vec::<bool>::new();
    let mut path = DerivationPath::derivation_path_with_indexes(
        indexes_root,
        hardened_root,
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    // • fingerprint:   |   ddebc675
    // • chain code:    |   8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69
    // • private:       |   68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3
    // • public:        |   008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64)],
        vec![true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("75c6ebdd").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H
    // • fingerprint:     |   13dab143
    // • chain code:      |   a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14
    // • private:         |   b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2
    // • public:          |   001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(1u32)],
        vec![true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("43b1da13").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H
    // • fingerprint:     |   ebe4cb29
    // • chain code:      |   2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c
    // • private:         |   92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9
    // • public:          |   00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32)],
        vec![true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("29cbe4eb").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H
    // • fingerprint:     |   316ec1c6
    // • chain code:      |   8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc
    // • private:         |   30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662
    // • public:          |   008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32), UInt256::from(2u32)],
        vec![true, true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("c6c16e31").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H/1000000000H
    // • fingerprint:     |   d6322ccd
    // • chain code:      |   68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230
    // • private:         |   8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793
    // • public:          |   003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32), UInt256::from(2u32), UInt256::from(1000000000u64)],
        vec![true, true, true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("cd2c32d6").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
}


#[test]
pub fn test_vector_2_derivation() {
    let manager = ChainsManager::new();
    let chain_type = ChainType::MainNet;
    // Test Vector 1
    let seed_data = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    manager.mainnet.wallet_with_seed(Seed::with_data(seed_data.clone()), false, chain_type);
    let chain = manager.mainnet.read().unwrap();
    let wallet = chain.wallets.first().unwrap();
    //--------------------------------------------------------------------------------------------------//
    // Chain m
    // • fingerprint: 00000000
    // • chain code: ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b
    // • private: 171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012
    // • public: 008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a
    //--------------------------------------------------------------------------------------------------//
    println!("••••••••••••••••••••••••••••••••••••••");
    let indexes_root = Vec::<UInt256>::new();
    let hardened_root = Vec::<bool>::new();
    let mut path = DerivationPath::derivation_path_with_indexes(
        indexes_root,
        hardened_root,
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    // • fingerprint:   |   31981b50
    // • chain code:    |   0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d
    // • private:       |   1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635
    // • public:        |   0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u64)],
        vec![true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("501b9831").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H
    // • fingerprint:     |   1e9411b1
    // • chain code:      |   138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f
    // • private:         |   ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4
    // • public:          |   005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(2147483647u64)],
        vec![true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("b111941e").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H
    // • fingerprint:     |   fcadf38c
    // • chain code:      |   73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90
    // • private:         |   3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c
    // • public:          |   002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32)],
        vec![true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("8cf3adfc").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H
    // • fingerprint:     |   aca70953
    // • chain code:      |   0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a
    // • private:         |   5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72
    // • public:          |   00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32), UInt256::from(2147483646u64)],
        vec![true, true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("5309a7ac").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H/2H
    // • fingerprint:     |   422c654b
    // • chain code:      |   5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4
    // • private:         |   551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d
    // • public:          |   0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0
    //--------------------------------------------------------------------------------------------------//
    let mut path = DerivationPath::derivation_path_with_indexes(
        vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32), UInt256::from(2147483646u64), UInt256::from(2u32)],
        vec![true, true, true, true, true],
        DerivationPathType::Unknown,
        KeyType::ED25519,
        DerivationPathReference::Root,
        chain_type,
        Weak::new());
    path.set_is_transient(true);
    path.set_wallet_unique_id(wallet.unique_id_as_str().to_string());
    path.generate_extended_public_key_from_seed_no_store(&seed_data);
    let private_key = path.private_key_from_seed(&seed_data).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("4b652c42").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
}
