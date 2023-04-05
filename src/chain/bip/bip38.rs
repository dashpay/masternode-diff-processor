use bip38::{Decrypt, Encrypt};
// use unicode_normalization::UnicodeNormalization;
use crate::chain::ScriptMap;
use crate::common::ChainType;
use crate::crypto::UInt256;
use crate::keys::{ECDSAKey, IKey};
use crate::util::address::address;
use crate::util::base58;

pub trait BIP38 {
    // decrypts a BIP38 key using the given passphrase or retuns nil if passphrase is incorrect
    fn key_with_bip38_key(key: &str, passphrase: &str, script: &ScriptMap) -> Option<Self> where Self: Sized;
    // generates an "intermediate code" for an EC multiply mode key, salt should be 64bits of random data
    // fn bip38_intermediate_code_with_salt(salt: u64, passphrase: &str) -> Option<String>;
    // generates an "intermediate code" for an EC multiply mode key with a lot and sequence number, lot must be less than
    // 1048576, sequence must be less than 4096, and salt should be 32bits of random data
    // fn bip38_intermediate_code_with_lot(lot: u32, sequence: u16, salt: u32, passphrase: &str) -> Option<String>;
    // generates a BIP38 key from an "intermediate code" and 24 bytes of cryptographically random data (seedb),
    // fn bip38_key_with_intermediate_code(code: &str, seedb: Vec<u8>, chain_type: ChainType) -> Option<String>;
    // encrypts receiver with passphrase and returns BIP38 key
    fn bip38_key_with_passphrase(&self, passphrase: &str, script: &ScriptMap) -> Option<String>;
}

impl BIP38 for ECDSAKey {

    fn key_with_bip38_key(key: &str, passphrase: &str, script: &ScriptMap) -> Option<Self> where Self: Sized {
        key.decrypt(passphrase, script.pubkey)
            .ok()
            .and_then(|(secret, compressed)| ECDSAKey::init_with_secret(UInt256(secret), compressed))
    }

    fn bip38_key_with_passphrase(&self, passphrase: &str, script: &ScriptMap) -> Option<String> {
        self.seckey.0.encrypt(passphrase, false, script.pubkey).ok()
    }
}
