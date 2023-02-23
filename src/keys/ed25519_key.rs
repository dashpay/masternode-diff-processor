use hashes::hex::ToHex;
use crate::crypto::{ECPoint, UInt160, UInt512};
use crate::derivation::{IIndexPath, IndexPath};
use crate::keys::{CryptoData, DHKey, IKey, KeyType};
use crate::UInt256;
use crate::chain::bip::dip14::derive_child_private_key_256_ed25519;
use crate::consensus::Encodable;
use crate::crypto::byte_util::Zeroable;

#[derive(Clone, Debug, Default)]
pub struct ED25519Key {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

impl IKey for ED25519Key {
    fn r#type(&self) -> KeyType {
        KeyType::ED25519
    }

    fn secret_key(&self) -> UInt256 {
        self.seckey
    }

    fn chaincode(&self) -> UInt256 {
        self.chaincode
    }

    fn fingerprint(&self) -> u32 {
        self.fingerprint
    }

    fn public_key_data(&self) -> Vec<u8> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.seckey.0);
        let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        ECPoint::from(signing_key.verifying_key()).0.to_vec()
    }

    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        if !self.is_extended {
            None
        } else {
            let mut writer = Vec::<u8>::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            writer.extend(self.public_key_data());
            Some(writer)
        }
    }

    fn private_derive_to_256bit_derivation_path<DPATH>(&self, derivation_path: &DPATH) -> Option<Self>
        where Self: Sized, DPATH: IIndexPath<Item=UInt256> {
        let mut signing_key = ed25519_dalek::SigningKey::from_bytes(&self.seckey.0);
        let mut chaincode = self.chaincode.clone();
        let mut fingerprint = 0u32;
        if !derivation_path.is_empty() {
            (0..derivation_path.length()).into_iter().for_each(|i| {
                if i == derivation_path.length() - 1 {
                    fingerprint = UInt160::hash160(ECPoint::from(ed25519_dalek::VerifyingKey::from(&signing_key)).as_ref()).u32_le();
                }
                let derivation = derivation_path.index_at_position(i);
                let is_hardened = derivation_path.hardened_at_position(i);
                derive_child_private_key_256_ed25519(&mut signing_key, &mut chaincode, &derivation, is_hardened);
            });
        }
        let seckey = UInt256(signing_key.to_bytes());
        Some(Self {
            seckey,
            chaincode,
            fingerprint,
            is_extended: true,
            compressed: true,
            ..Default::default()
        })
    }
    fn forget_private_key(&mut self) {
        if self.pubkey.is_empty() && !self.seckey.is_zero() {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.seckey.0);
            let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);
            self.pubkey = ECPoint::from(public_key).0.to_vec();
        }
        self.seckey = UInt256::MIN;
    }
}
impl DHKey for ED25519Key {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Option<Self> where Self: Sized {
        todo!()
    }
}

impl CryptoData<ED25519Key> for Vec<u8> {
    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &ED25519Key, public_key: &ED25519Key, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        todo!()
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &ED25519Key, public_key: &ED25519Key, iv_size: usize) -> Option<Vec<u8>> {
        todo!()
    }

    fn encrypt_with_dh_key_using_iv(&self, key: &ED25519Key, initialization_vector: Vec<u8>) -> Option<Vec<u8>> where ED25519Key: DHKey {
        todo!()
    }

    fn decrypt_with_dh_key_using_iv_size(&self, key: &ED25519Key, iv_size: usize) -> Option<Vec<u8>> where ED25519Key: DHKey {
        todo!()
    }
}

impl ED25519Key {
    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Option<Self> {
        todo!()
        // Self::init_with_secret(data.read_with::<UInt256>(&mut 36, byte::LE).unwrap(), true)
        //     .map(|s| Self::update_extended_params(s, data))
    }

    pub fn init_with_seed_data(seed: &Vec<u8>) -> Option<Self> {
        let i = UInt512::ed25519_seed_key(seed);
        Some(Self {
            seckey: UInt256::from(&i.0[..32]),
            chaincode: UInt256::from(&i.0[32..]),
            compressed: true,
            ..Default::default() })
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Option<Self> {
        todo!()
        // Self::init_with_public_key(data[36..].to_vec())
        //     .map(|s| Self::update_extended_params(s, data))
    }

    pub fn key_with_secret_data(data: &Vec<u8>, compressed: bool) -> Option<Self> {
        todo!()
        // Self::secret_key_from_bytes(data)
        //     .ok()
        //     .map(|seckey| Self::with_seckey(seckey, compressed))
    }

    pub fn key_with_public_key_data(data: &Vec<u8>) -> Option<Self> {
        assert!(!data.is_empty());
        todo!()
        // if data.len() != 33 && data.len() != 65 {
        //     None
        // } else {
        //     Self::public_key_from_bytes(data)
        //         .ok()
        //         .map(|pubkey| Self::with_pubkey_compressed(pubkey, data.len() == 33))
        // }
    }

    pub fn public_key_from_extended_public_key_data(data: &Vec<u8>, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        todo!()
    }
}
