use std::fmt::Debug;
use crate::BytesDecodable;
use crate::chain::ScriptMap;
use crate::chain::wallet::seed::Seed;
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::crypto::byte_util::AsBytes;
use crate::derivation::protocol::IDerivationPath;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::derivation::wallet_based_extended_private_key_location_string_for_unique_id;
use crate::keys::bls_key::BLSKey;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::{CryptoData, DHKey, IKey};
use crate::keys::ed25519_key::ED25519Key;
use crate::storage::keychain::Keychain;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    ECDSA = 0,
    BLS = 1,
    BLSBasic = 2,
    ED25519 = 3,
}

#[derive(Clone, Debug)]
pub enum Key {
    ECDSA(ECDSAKey),
    BLS(BLSKey),
    ED25519(ED25519Key),
}

impl From<ECDSAKey> for Key {
    fn from(value: ECDSAKey) -> Self {
        Key::ECDSA(value)
    }
}

impl From<BLSKey> for Key {
    fn from(value: BLSKey) -> Self {
        Key::BLS(value)
    }
}

impl From<ED25519Key> for Key {
    fn from(value: ED25519Key) -> Self {
        Key::ED25519(value)
    }
}

impl From<Key> for ECDSAKey {
    fn from(value: Key) -> Self {
        match value {
            Key::ECDSA(key) => key,
            _ => panic!("trying to unwrap bls from different key type")
        }
    }
}
impl From<Key> for BLSKey {
    fn from(value: Key) -> Self {
        match value {
            Key::BLS(key) => key,
            _ => panic!("trying to unwrap ecdsa from different key type")
        }
    }
}
impl From<Key> for ED25519Key {
    fn from(value: Key) -> Self {
        match value {
            Key::ED25519(key) => key,
            _ => panic!("trying to unwrap ed25519 from different key type")
        }
    }
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::ECDSA
    }
}

impl From<i16> for KeyType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => KeyType::ECDSA,
            1 => KeyType::BLS,
            2 => KeyType::BLSBasic,
            3 => KeyType::ED25519,
            _ => KeyType::default(),
        }
    }
}

impl From<KeyType> for i16 {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2,
            KeyType::ED25519 => 3,
        }
    }
}

impl From<&KeyType> for u8 {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2,
            KeyType::ED25519 => 3,
        }
    }
}

impl KeyType {

    pub fn derivation_string(&self) -> String {
        match self {
            KeyType::ECDSA | KeyType::ED25519 => "",
            KeyType::BLS | KeyType::BLSBasic  => "_BLS_",
        }.to_string()
    }

    pub(crate) fn public_key_from_extended_public_key_data(&self, data: &Vec<u8>, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        match self {
            KeyType::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyType::ED25519 => ED25519Key::public_key_from_extended_public_key_data(data, index_path),
            KeyType::BLS => BLSKey::public_key_from_extended_public_key_data(data, index_path, true),
            KeyType::BLSBasic => BLSKey::public_key_from_extended_public_key_data(data, index_path, false),
        }
    }

    pub(crate) fn private_key_from_extended_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::init_with_extended_private_key_data(data).map(|key| Key::ED25519(key)),
            KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_secret_data(data, true).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::key_with_secret_data(data, true).map(|key| Key::ED25519(key)),
            KeyType::BLS => BLSKey::key_with_private_key(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::key_with_private_key(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_seed_data(&self, seed: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_seed_data(seed).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::init_with_seed_data(seed).map(|key| Key::ED25519(key)),
            KeyType::BLS => BLSKey::extended_private_key_with_seed_data(seed, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::extended_private_key_with_seed_data(seed, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_public_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_public_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::key_with_public_key_data(data).map(|key| Key::ED25519(key)),
            KeyType::BLS => Some(Key::BLS(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), true))),
            KeyType::BLSBasic => Some(Key::BLS(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), false))),
        }
    }

    pub(crate) fn key_with_extended_public_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_public_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::init_with_extended_public_key_data(data).map(|key| Key::ED25519(key)),
            KeyType::BLS => BLSKey::init_with_extended_public_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_public_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_extended_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::ED25519 => ED25519Key::init_with_extended_private_key_data(data).map(|key| Key::ED25519(key)),
            KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }
    // fn private_derive_to_256bit_derivation_path<IPATH: IIndexPath, DPATH: IDerivationPath<IPATH> + IIndexPath>(&self, derivation_path: &DPATH) -> Option<Self> where Self: Sized {

    pub fn private_derive_to_256bit_derivation_path_from_seed_and_store<IPATH, DPATH>(&self, seed: &Seed, derivation_path: &DPATH, store_private_key: bool) -> Option<Key>
        where IPATH: IIndexPath, DPATH: IDerivationPath + IIndexPath<Item = UInt256>  {
        if let Some(seed_key) = self.key_with_seed_data(&seed.data) {
            println!("private_derive_to_256bit_derivation_path_from_seed_and_store: seed_key: {:?}", seed_key.clone());
            let derived = seed_key.private_derive_to_256bit_derivation_path(derivation_path);
            if let Some(mut ext_pk) = derived {
                let ext_pub_data = ext_pk.extended_private_key_data();
                let ext_prv_data = ext_pk.extended_public_key_data();
                println!("private_derive_to_256bit_derivation_path_from_seed_and_store: ext_prv_data: {:?} ext_pub_data: {:?}", ext_prv_data.clone(), ext_pub_data.clone());
                if !seed.unique_id.is_empty() {
                    Keychain::set_data(derivation_path.wallet_based_extended_public_key_location_string_for_wallet_unique_id(seed.unique_id_as_str()), ext_pub_data, false)
                        .expect("");
                    if store_private_key {
                        Keychain::set_data(wallet_based_extended_private_key_location_string_for_unique_id(seed.unique_id_as_str()), ext_prv_data, true)
                            .expect("");
                    }
                }
                ext_pk.forget_private_key();
                Some(ext_pk)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl IKey for Key {
    fn r#type(&self) -> KeyType {
        match self {
            Key::ECDSA(..) => KeyType::ECDSA,
            Key::ED25519(..) => KeyType::ED25519,
            Key::BLS(key) => if key.use_legacy { KeyType::BLS } else { KeyType::BLSBasic }
        }
    }

    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        match self {
            Key::ECDSA(key) => key.compact_sign(UInt256::from(data)),
            Key::BLS(key) => key.sign_digest(UInt256::from(data)).as_bytes().to_vec(),
            Key::ED25519(key) => key.sign(data)
        }
    }

    fn verify(&mut self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        match self {
            Key::ECDSA(key) => key.verify(message_digest, signature),
            Key::BLS(key) => key.verify_uint768(UInt256::from(message_digest), UInt768::from(signature)),
            Key::ED25519(key) => key.verify(message_digest, signature),
        }
    }

    fn secret_key(&self) -> UInt256 {
        match self {
            Key::ECDSA(key) => key.seckey,
            Key::BLS(key) => key.secret_key(),
            Key::ED25519(key) => key.secret_key(),
        }
    }

    fn chaincode(&self) -> UInt256 {
        match self {
            Key::ECDSA(key) => key.chaincode(),
            Key::BLS(key) => key.chaincode(),
            Key::ED25519(key) => key.chaincode(),
        }
    }

    fn fingerprint(&self) -> u32 {
        match self {
            Key::ECDSA(key) => key.fingerprint(),
            Key::BLS(key) => key.fingerprint(),
            Key::ED25519(key) => key.fingerprint(),
        }
    }

    fn private_key_data(&self) -> Option<Vec<u8>> {
        match self {
            Key::ECDSA(key) => key.private_key_data(),
            Key::BLS(key) => key.private_key_data(),
            Key::ED25519(key) => key.private_key_data(),
        }
    }

    fn public_key_data(&self) -> Vec<u8> {
        match self {
            Key::ECDSA(key) => key.public_key_data(),
            Key::BLS(key) => key.public_key_data(),
            Key::ED25519(key) => key.public_key_data(),
        }
    }

    fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        match self {
            Key::ECDSA(key) => key.extended_private_key_data(),
            Key::BLS(key) => key.extended_public_key_data(),
            Key::ED25519(key) => key.extended_public_key_data(),
        }
    }

    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        match self {
            Key::ECDSA(key) => key.extended_public_key_data(),
            Key::BLS(key) => key.extended_public_key_data(),
            Key::ED25519(key) => key.extended_public_key_data(),
        }
    }

    fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<Key> {
        match self {
            Key::ECDSA(key) => key.private_derive_to_path(index_path).map(Into::into),
            Key::BLS(key) => key.private_derive_to_path(index_path).map(Into::into),
            Key::ED25519(key) => key.private_derive_to_path(index_path).map(Into::into),
        }
    }

    fn private_derive_to_256bit_derivation_path<DPATH>(&self, derivation_path: &DPATH) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item=UInt256> {
        match self {
            Key::ECDSA(key) => key.private_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
            Key::BLS(key) => key.private_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
            Key::ED25519(key) => key.private_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
        }
    }

    fn public_derive_to_256bit_derivation_path<DPATH>(&mut self, derivation_path: &DPATH) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item = UInt256> {
        match self {
            Key::ECDSA(key) => key.public_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
            Key::BLS(key) => key.public_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
            Key::ED25519(key) => key.public_derive_to_256bit_derivation_path(derivation_path).map(Into::into),
        }
    }

    fn public_derive_to_256bit_derivation_path_with_offset<DPATH>(&mut self, derivation_path: &DPATH, offset: usize) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item = UInt256> {
        match self {
            Key::ECDSA(key) => key.public_derive_to_256bit_derivation_path_with_offset(derivation_path, offset).map(Into::into),
            Key::BLS(key) => key.public_derive_to_256bit_derivation_path_with_offset(derivation_path, offset).map(Into::into),
            Key::ED25519(key) => key.public_derive_to_256bit_derivation_path_with_offset(derivation_path, offset).map(Into::into),
        }
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        match self {
            Key::ECDSA(key) => key.serialized_private_key_for_script(script),
            Key::BLS(key) => key.serialized_private_key_for_script(script),
            Key::ED25519(key) => key.serialized_private_key_for_script(script),
        }
    }

    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        match self {
            Key::ECDSA(key) => key.hmac_256_data(data),
            Key::BLS(key) => key.hmac_256_data(data),
            Key::ED25519(key) => key.hmac_256_data(data),
        }
    }

    fn forget_private_key(&mut self) {
        match self {
            Key::ECDSA(key) => key.forget_private_key(),
            Key::BLS(key) => key.forget_private_key(),
            Key::ED25519(key) => key.forget_private_key(),
        }

    }
}

impl DHKey for Key {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Option<Self> where Self: Sized {
        match (public_key, private_key) {
            (Key::ECDSA(public_key), Key::ECDSA(private_key)) =>
                ECDSAKey::init_with_dh_key_exchange_with_public_key(public_key, private_key)
                    .map(Into::into),
            (Key::BLS(public_key), Key::BLS(private_key)) =>
                BLSKey::init_with_dh_key_exchange_with_public_key(public_key, private_key)
                    .map(Into::into),
            _ => None
        }
    }
}

impl CryptoData<Key> for Vec<u8> {
    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &Key, public_key: &Key, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        match (secret_key, public_key) {
            (Key::ECDSA(secret_key), Key::ECDSA(public_key)) =>
                <Vec<u8> as CryptoData<ECDSAKey>>::encrypt_with_secret_key_using_iv(self, secret_key, public_key, initialization_vector),
            (Key::BLS(secret_key), Key::BLS(public_key)) =>
                <Vec<u8> as CryptoData<BLSKey>>::encrypt_with_secret_key_using_iv(self, secret_key, public_key, initialization_vector),
            (Key::ED25519(secret_key), Key::ED25519(public_key)) =>
                <Vec<u8> as CryptoData<ED25519Key>>::encrypt_with_secret_key_using_iv(self, secret_key, public_key, initialization_vector),
            _ => None
        }
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &Key, public_key: &Key, iv_size: usize) -> Option<Vec<u8>> {
        match (secret_key, public_key) {
            (Key::ECDSA(secret_key), Key::ECDSA(public_key)) =>
                <Vec<u8> as CryptoData<ECDSAKey>>::decrypt_with_secret_key_using_iv_size(self, secret_key, public_key, iv_size),
            (Key::BLS(secret_key), Key::BLS(public_key)) =>
                <Vec<u8> as CryptoData<BLSKey>>::decrypt_with_secret_key_using_iv_size(self, secret_key, public_key, iv_size),
            (Key::ED25519(secret_key), Key::ED25519(public_key)) =>
                <Vec<u8> as CryptoData<ED25519Key>>::decrypt_with_secret_key_using_iv_size(self, secret_key, public_key, iv_size),
            _ => None
        }
    }

    fn encrypt_with_dh_key_using_iv(&self, key: &Key, initialization_vector: Vec<u8>) -> Option<Vec<u8>> where Key: DHKey {
        match key {
            Key::ECDSA(key) =>
                <Vec<u8> as CryptoData<ECDSAKey>>::encrypt_with_dh_key_using_iv(self, key, initialization_vector),
            Key::BLS(key) =>
                <Vec<u8> as CryptoData<BLSKey>>::encrypt_with_dh_key_using_iv(self, key, initialization_vector),
            Key::ED25519(key) =>
                <Vec<u8> as CryptoData<ED25519Key>>::encrypt_with_dh_key_using_iv(self, key, initialization_vector),
        }
    }

    fn decrypt_with_dh_key_using_iv_size(&self, key: &Key, iv_size: usize) -> Option<Vec<u8>> where Key: DHKey {
        match key {
            Key::ECDSA(key) =>
                <Vec<u8> as CryptoData<ECDSAKey>>::decrypt_with_dh_key_using_iv_size(self, key, iv_size),
            Key::BLS(key) =>
                <Vec<u8> as CryptoData<BLSKey>>::decrypt_with_dh_key_using_iv_size(self, key, iv_size),
            Key::ED25519(key) =>
                <Vec<u8> as CryptoData<ED25519Key>>::decrypt_with_dh_key_using_iv_size(self, key, iv_size),
        }
    }
}
