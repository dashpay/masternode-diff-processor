use std::fmt::Debug;
use crate::BytesDecodable;
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::crypto::byte_util::AsBytes;
use crate::derivation::protocol::IDerivationPath;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::derivation::wallet_based_extended_private_key_location_string_for_unique_id;
use crate::keys::bls_key::BLSKey;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::IKey;
use crate::storage::keychain::Keychain;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    ECDSA = 0,
    BLS = 1,
    BLSBasic = 2,
}

#[derive(Clone, Debug)]
pub enum Key {
    ECDSA(ECDSAKey),
    BLS(BLSKey),
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
            _ => KeyType::default(),
        }
    }
}

impl From<KeyType> for i16 {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2
        }
    }
}

impl From<&KeyType> for u8 {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2
        }
    }
}

impl KeyType {

    pub fn derivation_string(&self) -> String {
        match self {
            KeyType::ECDSA => "_BLS_",
            _ => ""
        }.to_string()
    }

    pub(crate) fn public_key_from_extended_public_key_data(&self, data: &Vec<u8>, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        match self {
            KeyType::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyType::BLS => BLSKey::public_key_from_extended_public_key_data(data, index_path, true),
            KeyType::BLSBasic => BLSKey::public_key_from_extended_public_key_data(data, index_path, false),
        }
    }

    pub(crate) fn private_key_from_extended_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_secret(data, true).map(|key| Key::ECDSA(key)),
            KeyType::BLS => BLSKey::key_with_private_key(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::key_with_private_key(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_seed_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_seed_data(data).map(|key| Key::ECDSA(key)),
            KeyType::BLS => BLSKey::extended_private_key_with_seed_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::extended_private_key_with_seed_data(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_public_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_public_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::BLS => Some(Key::BLS(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), true))),
            KeyType::BLSBasic => Some(Key::BLS(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), false))),
        }
    }

    pub(crate) fn key_with_extended_public_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_public_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::BLS => BLSKey::init_with_extended_public_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_public_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }

    pub(crate) fn key_with_extended_private_key_data(&self, data: &Vec<u8>) -> Option<Key> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data).map(|key| Key::ECDSA(key)),
            KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true).map(|key| Key::BLS(key)),
            KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false).map(|key| Key::BLS(key)),
        }
    }
    // fn private_derive_to_256bit_derivation_path<IPATH: IIndexPath, DPATH: IDerivationPath<IPATH> + IIndexPath>(&self, derivation_path: &DPATH) -> Option<Self> where Self: Sized {

    pub fn private_derive_to_256bit_derivation_path_from_seed_and_store<IPATH, DPATH>(&self, seed: &Vec<u8>, derivation_path: &DPATH, wallet_unique_id: Option<&String>, store_private_key: bool) -> Option<Key>
        where IPATH: IIndexPath, DPATH: IDerivationPath<IPATH> + IIndexPath  {
        if let Some(seed_key) = self.key_with_seed_data(seed) {
            let derived = seed_key.private_derive_to_256bit_derivation_path(derivation_path);
            if let Some(mut ext_pk) = derived {
                let ext_pub_data = ext_pk.extended_private_key_data();
                let ext_prv_data = ext_pk.extended_public_key_data();
                if let Some(unique_id) = wallet_unique_id {
                    Keychain::set_data(derivation_path.wallet_based_extended_public_key_location_string_for_wallet_unique_id(unique_id), ext_pub_data, false).expect("");
                    if store_private_key {
                        Keychain::set_data(wallet_based_extended_private_key_location_string_for_unique_id(unique_id), ext_prv_data, true).expect("");
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
            Key::BLS(key) => if key.use_legacy { KeyType::BLS } else { KeyType::BLSBasic }
        }
    }

    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        match self {
            Key::ECDSA(key) => key.compact_sign(UInt256::from_bytes_force(data)),
            Key::BLS(key) => key.sign_digest(UInt256::from_bytes_force(data)).as_bytes().to_vec()
        }
    }

    fn verify(&mut self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        match self {
            Key::ECDSA(key) => key.verify(message_digest, signature),
            Key::BLS(key) => key.verify_uint768(UInt256::from_bytes_force(message_digest), UInt768::from_bytes_force(signature))
        }
    }

    fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<Key> {
        match self {
            Key::ECDSA(key) => key.private_derive_to_path(index_path).map(Into::into),
            Key::BLS(key) => key.private_derive_to_path(index_path).map(Into::into),
        }
    }
}
