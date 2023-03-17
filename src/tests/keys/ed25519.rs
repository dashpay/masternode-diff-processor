use hashes::hex::{FromHex, ToHex};
use crate::crypto::{ECPoint, UInt256, UInt512};

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
