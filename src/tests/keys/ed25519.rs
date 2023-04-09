use hashes::hex::{FromHex, ToHex};
use crate::crypto::{UInt256, UInt512};

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
    let public_key = UInt256::from(ed25519_dalek::VerifyingKey::from(&signing_key));
    let chaincode = UInt256::from(&i.0[32..]);
    assert_eq!(signing_key.to_bytes().to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    // assert_eq!(public_key.0.to_hex(), "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
    assert_eq!(public_key.0.to_hex(), "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
}

// #[test]
// pub fn test_extended() {
//     // ED25519Key.public_key_from_extended_public_key_data: 5a498e342c3e07d4eeff8455cbe69e6c775d520e92a54e63e69c97d4372bedd5fad030380004fc25f480aa053500f7d1004ca790258d7c1e019c76153e482d1786096b9776, [0], []
//     // ED25519Key.derive_child_public_key: 0004fc25f480aa053500f7d1004ca790258d7c1e019c76153e482d1786096b9776 2c3e07d4eeff8455cbe69e6c775d520e92a54e63e69c97d4372bedd5fad03038 0
//     // ED25519Key.derive_child_public_key.i: 085bf102195e8b8178ad265e7ccf69107a7f71c3e28ee196c33c41a1676c5f93d2aa3b49411c534fde232092e7da02363cda697ee959687e551789365279e717
//     // ED25519Key.public_key_from_extended_public_key_data: 5a498e342c3e07d4eeff8455cbe69e6c775d520e92a54e63e69c97d4372bedd5fad030380004fc25f480aa053500f7d1004ca790258d7c1e019c76153e482d1786096b9776, [1], []
//     // ED25519Key.derive_child_public_key: 0004fc25f480aa053500f7d1004ca790258d7c1e019c76153e482d1786096b9776 2c3e07d4eeff8455cbe69e6c775d520e92a54e63e69c97d4372bedd5fad03038 0
//     // ED25519Key.derive_child_public_key.i: 3f30daf09ca1e4c3ef9bd0db0e7a663e0358a045da5553baa3737e401a9936d2374a4ef56273b970f454b721ba308478d44fb3010d227642aa10cc7fbde32cf1
//
//     let extended_public_key_data = Vec::from_hex("5a498e342c3e07d4eeff8455cbe69e6c775d520e92a54e63e69c97d4372bedd5fad030380004fc25f480aa053500f7d1004ca790258d7c1e019c76153e482d1786096b9776").unwrap();
//     let key = ED25519Key::key_with_extended_public_key_data(&extended_public_key_data).unwrap();
//     let extended_public_key_data = key.extended_public_key_data().unwrap();
//     println!("extended_public_key_data: {}", extended_public_key_data.to_hex());
//     let index_path = IndexPath::new(vec![0u32]);
//     let key = ED25519Key::public_key_from_extended_public_key_data(&extended_public_key_data, &index_path).unwrap();
//     println!("extended_public_key_data: {:?}", key.to_hex());
//     let index_path = IndexPath::new(vec![1u32]);
//     let key = ED25519Key::public_key_from_extended_public_key_data(&extended_public_key_data, &index_path).unwrap();
//     println!("extended_public_key_data: {:?}", key.to_hex());
//
//
// }
