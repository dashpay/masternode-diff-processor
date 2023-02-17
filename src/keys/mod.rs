pub mod bls_key;
pub mod key;
pub mod ecdsa_key;

pub use self::key::Key;
pub use self::key::KeyType;
pub use self::bls_key::BLSKey;
pub use self::ecdsa_key::ECDSAKey;

use std::fmt::Debug;
use common_crypto::cryptor;
use crate::UInt256;
use crate::chain::ScriptMap;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::util::Address::with_public_key_data;

pub trait IKey: Send + Sync + Debug {
    fn r#type(&self) -> KeyType {
        panic!("Should be overriden in implementation")
    }
    fn address_with_public_key_data(&mut self, script_map: &ScriptMap) -> String {
        with_public_key_data(&self.public_key_data(), script_map)
    }
    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn verify(&mut self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        panic!("Should be overriden in implementation")
    }
    fn private_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn public_key_data(&self) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<Self> where Self: Sized {
        panic!("Should be overriden in implementation")
    }
    fn private_derive_to_256bit_derivation_path<DPATH>(&self, derivation_path: &DPATH) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item = UInt256> {
        self.private_derive_to_path(&derivation_path.base_index_path())
    }
    fn public_derive_to_256bit_derivation_path<DPATH>(&mut self, derivation_path: &DPATH) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item = UInt256> {
        self.public_derive_to_256bit_derivation_path_with_offset(derivation_path, 0)
    }
    fn public_derive_to_256bit_derivation_path_with_offset<DPATH>(&mut self, derivation_path: &DPATH, offset: usize) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item = UInt256> {
        panic!("Should be overriden in implementation")
    }
    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        panic!("Should be overriden in implementation")
    }
    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        panic!("Should be overriden in implementation")
    }
    fn forget_private_key(&mut self) {
        panic!("Should be overriden in implementation")
    }
}

pub trait DHKey: Send + Sync + Debug {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Option<Self> where Self: Sized;
}

pub trait IEncryptableKey: Send + Sync + Debug {

    #[inline]
    fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
        use secp256k1::rand;
        use secp256k1::rand::distributions::Uniform;
        use secp256k1::rand::Rng;
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        (0..size).map(|_| rng.sample(&range)).collect()
    }

    // - (nullable NSData *)encryptWithBLSSecretKey:(DSBLSKey *)secretKey forPublicKey:(DSBLSKey *)peerPubKey usingInitializationVector:(NSData *)ivData {
    fn encrypt_data_for_public_key_using_initialization_vector(&self, data: &Vec<u8>, public_key: Self, initialization_vector: &Vec<u8>) -> Vec<u8>;

    // - (nullable NSData *)decryptWithBLSSecretKey:(DSBLSKey *)secretKey fromPublicKey:(DSBLSKey *)peerPubKey usingIVSize:(NSUInteger)ivSize {
    fn decrypt_data_from_public_key_using_iv_size(&self, data: &Vec<u8>, public_key: Self, iv_size: u64) -> Vec<u8>;

    // - (nullable NSData *)encryptWithBLSSecretKey:(DSBLSKey *)secretKey forPublicKey:(DSBLSKey *)peerPubKey usingInitializationVector:(NSData *)ivData {
    fn encrypt_data_for_public_key<K: IEncryptableKey>(&self, data: &Vec<u8>, public_key: K) -> Vec<u8>;
    fn encrypt_data(&self, data: &Vec<u8>) -> Vec<u8> where Self: IEncryptableKey;
    fn decrypt_with_secret_key() -> Self;
}

pub const CC_BLOCK_SIZE_AES128: usize = 16;
pub const CC_ENCRYPT: u8 = 0;
pub const CC_DECRYPT: u8 = 1;

pub trait CryptoData<K: IKey + Clone>: Send + Sync + Debug where Vec<u8>: CryptoData<K> {

    #[inline]
    fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
        use secp256k1::rand;
        use secp256k1::rand::distributions::Uniform;
        use secp256k1::rand::Rng;
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        (0..size).map(|_| rng.sample(&range)).collect()
    }

    fn encrypt(input: impl AsRef<[u8]>, config: cryptor::Config) -> Option<Vec<u8>> {
        cryptor::Cryptor::decrypt(&config, input).ok()
    }

    fn decrypt(input: impl AsRef<[u8]>, config: cryptor::Config) -> Option<Vec<u8>> {
        cryptor::Cryptor::decrypt(&config, input).ok()
    }

    // fn encrypt(input: impl AsRef<[u8]>, key_data: [u8; 32], iv_data: [u8; 16]) -> Option<Vec<u8>> {
    //     cryptor::Cryptor::decrypt(&cryptor::Config::AES256 {
    //         mode: cryptor::Mode::CTR,
    //         iv: Some(&iv_data),
    //         key: &key_data,
    //     }, input).ok()
    // }
    //
    // fn decrypt(input: impl AsRef<[u8]>, key_data: [u8; 32], iv_data: [u8; 16]) -> Option<Vec<u8>> {
    //     cryptor::Cryptor::decrypt(&cryptor::Config::AES256 {
    //         mode: cryptor::Mode::CTR,
    //         iv: Some(&iv_data),
    //         key: &key_data,
    //     }, input).ok()
    // }


    fn encrypt_with_secret_key(&mut self, secret_key: &K, public_key: &K) -> Option<Vec<u8>> {
        self.encrypt_with_secret_key_using_iv(secret_key, public_key, Self::random_initialization_vector_of_size(CC_BLOCK_SIZE_AES128))
    }

    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &K, public_key: &K, initialization_vector: Vec<u8>) -> Option<Vec<u8>>;

    fn decrypt_with_secret_key(&mut self, secret_key: &K, public_key: &K) -> Option<Vec<u8>> {
        self.decrypt_with_secret_key_using_iv_size(secret_key, public_key, CC_BLOCK_SIZE_AES128)
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &K, public_key: &K, iv_size: usize) -> Option<Vec<u8>>;


    // DHKey
    fn encrypt_with_dh_key(&self, key: &K) -> Option<Vec<u8>> where K: DHKey {
        self.encrypt_with_dh_key_using_iv(key, Self::random_initialization_vector_of_size(CC_BLOCK_SIZE_AES128))
    }
    fn encrypt_with_dh_key_using_iv(&self, key: &K, initialization_vector: Vec<u8>) -> Option<Vec<u8>> where K: DHKey;
    fn decrypt_with_dh_key(&self, key: &K) -> Option<Vec<u8>> where K: DHKey {
        self.decrypt_with_dh_key_using_iv_size(key, CC_BLOCK_SIZE_AES128)
    }
    fn decrypt_with_dh_key_using_iv_size(&self, key: &K, iv_size: usize) -> Option<Vec<u8>> where K: DHKey;




    fn encapsulated_dh_decryption_with_keys(&mut self, keys: Vec<K>) -> Option<Vec<u8>> where K: DHKey {
        assert!(keys.len() > 0, "There should be at least one key");
        match &keys[..] {
            [first_key, other @ ..] if !other.is_empty() =>
                self.decrypt_with_dh_key(first_key)
                    .and_then(|mut data| data.encapsulated_dh_decryption_with_keys(other.to_vec())),
            [first_key] =>
                self.decrypt_with_dh_key(first_key),
            _ => None
        }
    }

    fn encapsulated_dh_decryption_with_keys_using_iv_size(&mut self, keys: Vec<K>, iv_size: usize) -> Option<Vec<u8>> where K: DHKey {
        assert!(keys.len() > 1, "There should be at least two key (first pair)");
        match &keys[..] {
            [first_key, other @ ..] if other.len() > 1 =>
                self.decrypt_with_secret_key_using_iv_size(other.first().unwrap(), first_key, iv_size)
                    .and_then(|mut data| data.encapsulated_dh_decryption_with_keys_using_iv_size(other.to_vec(), iv_size)),
            [first_key, second_key] =>
                self.decrypt_with_secret_key_using_iv_size(second_key, first_key, iv_size),
            _ => None
        }
    }

    fn encapsulated_dh_encryption_with_keys(&mut self, keys: Vec<K>) -> Option<Vec<u8>> where K: DHKey {
        assert!(!keys.is_empty(), "There should be at least one key");
        match &keys[..] {
            [first, other @ ..] if !other.is_empty() =>
                self.encrypt_with_dh_key(first)
                    .and_then(|mut data| data.encapsulated_dh_encryption_with_keys(other.to_vec())),
            [first] => self.encrypt_with_dh_key(first),
            _ => None
        }
    }

    fn encapsulated_dh_encryption_with_keys_using_iv(&mut self, keys: Vec<K>, initialization_vector: Vec<u8>) -> Option<Vec<u8>> where K: DHKey {
        assert!(!keys.is_empty(), "There should be at least one key");
        match &keys[..] {
            [first, other @ ..] if !other.is_empty() =>
                self.encrypt_with_dh_key(first)
                    .and_then(|mut data| data.encapsulated_dh_encryption_with_keys_using_iv(other.to_vec(), initialization_vector)),
            [first] => self.encrypt_with_dh_key(first),
            _ => None
        }
    }
}
