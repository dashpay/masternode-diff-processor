use bls_signatures::bip32::{ExtendedPrivateKey, ExtendedPublicKey};
use bls_signatures::{BasicSchemeMPL, BlsError, G1Element, G2Element, LegacySchemeMPL, PrivateKey, Scheme};
use common_crypto::cryptor;
use hashes::{Hash, sha256, sha256d};
use hashes::hex::{FromHex, ToHex};
use crate::chain::params::ScriptMap;
use crate::chain::wallet::seed::Seed;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, BytesDecodable, Zeroable};
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::keys::{CryptoData, DHKey, IKey};
use crate::keys::key::KeyType;
use crate::util::base58;
use crate::util::data_ops::hex_with_data;

#[derive(Clone, Debug, Default)]
pub struct BLSKey {
    pub extended_private_key_data: Vec<u8>,
    pub extended_public_key_data: Vec<u8>,
    // pub chain_code: ChainCode,
    pub chain_code: UInt256,
    pub secret_key: UInt256,
    pub public_key: UInt384,
    pub use_legacy: bool,
}

impl BLSKey {

    pub fn key_with_secret_hex(string: &str, use_legacy: bool) -> Option<Self> {
        Vec::from_hex(string)
            .ok()
            .map(|data| Self::key_with_seed_data(&Seed::with_data(data), use_legacy))
    }

    pub fn key_with_private_key(data: &Vec<u8>, use_legacy: bool) -> Option<Self> {
        UInt256::from_bytes(data, &mut 0)
            .and_then(|secret_key| PrivateKey::from_bytes(data, false)
                .ok()
                .and_then(|bls_private_key| bls_private_key.g1_element()
                    .ok()
                    .map(|bls_public_key|
                        Self {
                            secret_key,
                            public_key: UInt384(*if use_legacy { bls_public_key.serialize() } else { bls_public_key.serialize_legacy() }),
                            use_legacy,
                            ..Default::default() })))
    }

    pub fn key_with_public_key(public_key: UInt384, use_legacy: bool) -> Self {
        Self { public_key, use_legacy, ..Default::default() }
    }

    pub fn product(&self, public_key: &BLSKey) -> Option<[u8; 48]> {
        match (self.bls_private_key(), public_key.bls_public_key(), self.use_legacy) {
            (Ok(priv_key), Ok(pub_key), use_legacy) if public_key.use_legacy == use_legacy =>
                (priv_key * pub_key).map(|pk| if use_legacy { *pk.serialize_legacy() } else { *pk.serialize() }).ok(),
            _ => None
        }
    }
}

impl IKey for BLSKey {
    fn r#type(&self) -> KeyType {
        KeyType::BLS // &KeyType::BLSBasic
    }
    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        self.sign_digest( UInt256::from_bytes_force(data)).as_bytes().to_vec()
    }
    fn verify(&mut self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        self.verify_uint768(UInt256::from_bytes_force(message_digest), UInt768::from_bytes_force(signature))
    }

    fn private_key_data(&self) -> Option<Vec<u8>> where Self: Sized {
        (!self.secret_key.is_zero())
            .then_some(self.secret_key.0.to_vec())
    }

    fn public_key_data(&self) -> Vec<u8> {
        self.public_key.0.to_vec()
    }

    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        Some(self.extended_public_key_data.clone())
    }

    fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<Self> where Self: Sized {
        ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_slice())
            .ok()
            .and_then(|bls_extended_private_key|
                Self::init_with_bls_extended_private_key(&Self::derive(bls_extended_private_key, index_path, self.use_legacy), self.use_legacy))
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        // if (uint256_is_zero(self.secretKey)) return nil;
        // NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
        let mut writer = Vec::<u8>::new();
        script.privkey.enc(&mut writer);
        self.secret_key.enc(&mut writer);
        b'\x02'.enc(&mut writer);
        base58::check_encode_slice(&writer)
    }

    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        UInt256::hmac::<sha256::Hash>(self.secret_key.as_bytes(), data)

    }

    fn forget_private_key(&mut self) {
        self.secret_key = UInt256::MIN;
    }
}

impl BLSKey {

    pub fn init_with_extended_private_key_data(data: &Vec<u8>, use_legacy: bool) -> Option<Self> {
        ExtendedPrivateKey::from_bytes(data)
            .ok()
            .and_then(|pk| Self::init_with_bls_extended_private_key(&pk, use_legacy))
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>, use_legacy: bool) -> Option<Self> {
        if use_legacy {
            ExtendedPublicKey::from_bytes_legacy(data)
        } else {
            ExtendedPublicKey::from_bytes(data)
        }.ok().map(|pk| Self::init_with_bls_extended_public_key(&pk, use_legacy))
    }

    /// A little recursive magic since extended private keys can't be re-assigned in the library
    pub fn derive(extended_private_key: ExtendedPrivateKey, index_path: &IndexPath<u32>, use_legacy: bool) -> ExtendedPrivateKey {
        if index_path.is_empty() {
            extended_private_key
        } else {
            let top_index_path = index_path.index_at_position(0);
            let sk_child = if use_legacy {
                extended_private_key.private_child_legacy(top_index_path)
            } else {
                extended_private_key.private_child(top_index_path)
            };
            Self::derive(sk_child, &index_path.index_path_by_removing_first_index(), use_legacy)
        }
    }

    pub fn can_public_derive(index_path: IndexPath<u32>, use_legacy: bool) -> bool {
        for i in 0..index_path.length() {
            if index_path.index_at_position(0) >> 31 == 1 {
                return false;
            }
        }
        true
    }

    pub fn public_derive(extended_public_key: ExtendedPublicKey, index_path: &IndexPath<u32>, use_legacy: bool) -> ExtendedPublicKey {
        if index_path.is_empty() {
            extended_public_key
        } else {
            let top_index_path = index_path.index_at_position(0);
            assert_eq!(top_index_path >> 31, 0, "There should be no hardened derivation if you wish to derive extended public keys");
            let pk_child = if use_legacy {
                extended_public_key.public_child_legacy(top_index_path)
            } else {
                extended_public_key.public_child(top_index_path)
            };
            Self::public_derive(pk_child, &index_path.index_path_by_removing_first_index(), use_legacy)
        }
    }

    pub fn key_with_seed_data(seed: &Seed, use_legacy: bool) -> Self {
        let bls_private_key = PrivateKey::from_bip32_seed(&seed.data);
        let bls_public_key = bls_private_key.g1_element().unwrap();
        println!("key_with_seed_data.private_key.serialize: {:?}", &*bls_private_key.serialize());
        let secret_key = UInt256::from_bytes_force(&*bls_private_key.serialize());
        let public_key = UInt384(*if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        });
        println!("key_with_seed_data.seed: {:?}", seed.data.to_hex());
        println!("key_with_seed_data.secret_key: {:?}", secret_key);
        println!("key_with_seed_data.public_key: {:?}", public_key);
        println!("key_with_seed_data.use_legacy: {:?}", use_legacy);
        Self {
            secret_key,
            public_key,
            use_legacy,
            // engine: if use_legacy { LegacySchemeMPL::new() } else { BasicSchemeMPL::new() },
            ..Default::default()
        }
    }


    pub fn init_with_bls_extended_public_key(bls_extended_public_key: &ExtendedPublicKey, use_legacy: bool) ->  Self {
        let extended_public_key_data = if use_legacy {
            bls_extended_public_key.serialize_legacy()
        } else {
            bls_extended_public_key.serialize()
        }.to_vec();
        let bls_public_key = bls_extended_public_key.public_key();
        let public_key_data = if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        };
        Self {
            extended_private_key_data: vec![],
            extended_public_key_data,
            chain_code: UInt256(*bls_extended_public_key.chain_code().serialize()),
            secret_key: UInt256::MIN,
            public_key: UInt384(*public_key_data),
            use_legacy
        }
    }

    pub fn init_with_bls_extended_private_key(bls_extended_private_key: &ExtendedPrivateKey, use_legacy: bool) -> Option<Self> {
        let extended_private_key_data = bls_extended_private_key.serialize();
        let extended_public_key_opt = if use_legacy {
            bls_extended_private_key.extended_public_key_legacy()
        } else {
            bls_extended_private_key.extended_public_key()
        };
        if extended_public_key_opt.is_err() {
            println!("Can't restore extended_public_key");
            return None;
        }
        let extended_public_key = extended_public_key_opt.unwrap();
        let extended_public_key_data = if use_legacy {
            extended_public_key.serialize_legacy()
        } else {
            extended_public_key.serialize()
        };
        let chain_code = UInt256(*bls_extended_private_key.chain_code().serialize());
        let bls_private_key = bls_extended_private_key.private_key();
        let bls_public_key_opt = bls_private_key.g1_element();
        if bls_public_key_opt.is_err() {
            println!("Can't restore bls_public_key");
            return None;
        }
        let bls_public_key = bls_public_key_opt.unwrap();
        let bls_public_key_bytes = if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        };
        if let Some(secret_key) = UInt256::from_bytes(bls_private_key.serialize().as_slice(), &mut 0) {
            Some(Self {
                extended_private_key_data: extended_private_key_data.to_vec(),
                extended_public_key_data: extended_public_key_data.to_vec(),
                chain_code,
                secret_key,
                public_key: UInt384(*bls_public_key_bytes),
                use_legacy,
                // engine: if use_legacy { LegacySchemeMPL::new() } else { BasicSchemeMPL::new() }
            })
        } else {
            println!("Can't restore secret_key");
            return None;
        }
    }

    pub fn extended_private_key_with_seed_data(seed: &Seed, use_legacy: bool) -> Option<Self> {
        ExtendedPrivateKey::from_seed(&seed.data)
            .ok()
            .and_then(|pk| Self::init_with_bls_extended_private_key(&pk, use_legacy))
    }


    pub fn public_key_from_extended_public_key_data(data: &Vec<u8>, index_path: &IndexPath<u32>, use_legacy: bool) -> Option<Vec<u8>> {
        if use_legacy {
            ExtendedPublicKey::from_bytes_legacy(data)
        } else {
            ExtendedPublicKey::from_bytes(data)
        }
            .ok()
            .and_then(|bls_extended_public_key|
                BLSKey::init_with_bls_extended_public_key(&bls_extended_public_key, use_legacy)
                    .public_derive_to_path(index_path)
                    .map(|pk| pk.public_key_data()))
    }

    pub fn public_key_fingerprint(&self) -> u32 {
        if self.use_legacy {
            G1Element::from_bytes_legacy(self.public_key.as_bytes()).unwrap().fingerprint_legacy()
        } else {
            G1Element::from_bytes(self.public_key.as_bytes()).unwrap().fingerprint()
        }
    }

    pub fn secret_key_string(&self) -> String {
        if self.secret_key.is_zero() {
            String::new()
        } else {
            hex_with_data(self.secret_key.as_bytes())
        }
    }

    pub fn serialized_private_key_for_script_map(&self, map: &ScriptMap) -> Option<String> {
        if self.secret_key.is_zero() {
            None
        } else {
            // todo: impl securebox here
            //NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
            let mut writer = Vec::<u8>::with_capacity(34);
            map.privkey.enc(&mut writer);
            self.secret_key.enc(&mut writer);
            b'\x02'.enc(&mut writer);
            Some(base58::check_encode_slice(&writer))
        }
    }

    pub fn public_derive_to_path(&mut self, index_path: &IndexPath<u32>) -> Option<Self> {
        if (self.extended_public_key_data().is_none() || self.extended_public_key_data().unwrap().is_empty()) && self.extended_private_key_data.is_empty() {
            None
        } else if let Some(bls_extended_public_key) = self.bls_extended_public_key() {
            Some(BLSKey::init_with_bls_extended_public_key(&BLSKey::public_derive(bls_extended_public_key, index_path, self.use_legacy), self.use_legacy))
        } else {
            None
        }
    }

    pub fn bls_extended_public_key(&mut self) -> Option<ExtendedPublicKey> {
        if let Some(bytes) = self.extended_public_key_data() {
            if self.use_legacy { ExtendedPublicKey::from_bytes_legacy(&bytes) } else { ExtendedPublicKey::from_bytes(&bytes) }.ok()
        } else if let Some(bytes) = self.extended_private_key_data() {
            ExtendedPrivateKey::from_bytes(&bytes).and_then(|pk| pk.extended_public_key()).ok()
        } else {
            None
        }
    }

    pub fn extended_private_key(&self) -> Option<Self> {
        if let Ok(pk) = self.bls_extended_private_key() {
            Self::init_with_bls_extended_private_key(&pk, self.use_legacy)
        } else {
            None
        }
    }

    pub fn bls_extended_private_key(&self) -> Result<ExtendedPrivateKey, BlsError> {
        ExtendedPrivateKey::from_bytes(&self.extended_private_key_data)
    }

    pub(crate) fn bls_private_key(&self) -> Result<PrivateKey, BlsError> {
        if !self.secret_key.is_zero() {
            PrivateKey::from_bytes(self.secret_key.as_bytes(), true)
        } else {
            ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_slice()).map(|ext_pk| ext_pk.private_key())
        }
    }

    pub(crate) fn bls_public_key(&self) -> Result<G1Element, BlsError> {
        if self.public_key.is_zero() {
            self.bls_private_key().and_then(|bls_pk| bls_pk.g1_element())
        } else if self.use_legacy {
            G1Element::from_bytes_legacy(self.public_key.as_bytes())
        } else {
            G1Element::from_bytes(self.public_key.as_bytes())
        }
    }

    pub(crate) fn bls_public_key_serialized(&self) -> Option<[u8; 48]> {
        self.bls_public_key()
            .ok()
            .map(|pk| if self.use_legacy { *pk.serialize_legacy() } else { *pk.serialize() })
    }

    /// Signing
    pub fn sign_data(&self, data: &Vec<u8>) -> UInt768 {
        if self.secret_key.is_zero() && self.extended_private_key_data.is_empty() {
            UInt768::MAX
        } else if let Ok(bls_private_key) = self.bls_private_key() {
            let hash = sha256d::Hash::hash(data).into_inner();
            let signature = if self.use_legacy {
                LegacySchemeMPL::new().sign(&bls_private_key, &hash).serialize_legacy()
            } else {
                BasicSchemeMPL::new().sign(&bls_private_key, &hash).serialize()
            };
            UInt768(*signature)
        } else {
            UInt768::MAX
        }
    }

    pub fn sign_data_single_sha256(&self, data: &Vec<u8>) -> UInt768 {
        if self.secret_key.is_zero() && self.extended_private_key_data.is_empty() {
            UInt768::MAX
        } else if let Ok(bls_private_key) = self.bls_private_key() {
            let hash = sha256::Hash::hash(data).into_inner();
            let signature = if self.use_legacy {
                LegacySchemeMPL::new().sign(&bls_private_key, &hash).serialize_legacy()
            } else {
                BasicSchemeMPL::new().sign(&bls_private_key, &hash).serialize()
            };
            UInt768(*signature)
        } else {
            UInt768::MAX
        }
    }

    pub fn sign_digest(&self, md: UInt256) -> UInt768 {
        if self.secret_key.is_zero() && self.extended_private_key_data.is_empty() {
            UInt768::MIN
        } else if let Ok(bls_private_key) = self.bls_private_key() {
            let bls_signature = if self.use_legacy {
                LegacySchemeMPL::new().sign(&bls_private_key, md.as_bytes()).serialize_legacy()
            } else {
                BasicSchemeMPL::new().sign(&bls_private_key, md.as_bytes()).serialize()
            };
            UInt768(*bls_signature)
        } else {
            UInt768::MIN
        }
    }

    pub fn sign_message_digest(&self, digest: UInt256, completion: fn(bool, UInt768)) {
        let signature = self.sign_digest(digest);
        completion(!signature.is_zero(), signature)
    }


    /// Verification

    pub fn verify_uint768(&self, digest: UInt256, signature: UInt768) -> bool {
        if let Ok(bls_public_key) = self.bls_public_key() {
            if self.use_legacy {
                LegacySchemeMPL::new().verify(&bls_public_key, digest.as_bytes(), &G2Element::from_bytes_legacy(signature.as_bytes()).unwrap())
            } else {
                BasicSchemeMPL::new().verify(&bls_public_key, digest.as_bytes(), &G2Element::from_bytes(signature.as_bytes()).unwrap())
            }
        } else {
            false
        }
    }

    pub fn verify_with_public_key(digest: UInt256, signature: UInt768, public_key: UInt384, use_legacy: bool) -> bool {
        if let Ok(bls_public_key) = BLSKey::key_with_public_key(public_key, use_legacy).bls_public_key() {
            if use_legacy {
                LegacySchemeMPL::new().verify(&bls_public_key, digest.as_bytes(), &G2Element::from_bytes_legacy(signature.as_bytes()).unwrap())
            } else {
                BasicSchemeMPL::new().verify(&bls_public_key, digest.as_bytes(), &G2Element::from_bytes(signature.as_bytes()).unwrap())
            }
        } else {
            false
        }
    }

    pub fn verify_secure_aggregated(digest: UInt256, signature: UInt768, public_keys: Vec<BLSKey>, use_legacy: bool) -> bool {
        if use_legacy {
            if let Ok(bls_signature) = G2Element::from_bytes_legacy(signature.as_bytes()) {
                let bls_public_keys: Vec<_> = public_keys.into_iter().filter_map(|pk| pk.bls_public_key().ok()).collect::<Vec<_>>();
                LegacySchemeMPL::new().verify_secure(bls_public_keys.iter().collect::<Vec<&G1Element>>(), digest.as_bytes(), &bls_signature)
            } else {
                false
            }
        } else {
            if let Ok(bls_signature) = G2Element::from_bytes(signature.as_bytes()) {
                let bls_public_keys: Vec<_> = public_keys.into_iter().filter_map(|pk| pk.bls_public_key().ok()).collect::<Vec<_>>();
                BasicSchemeMPL::new().verify_secure(bls_public_keys.iter().collect::<Vec<&G1Element>>(), digest.as_bytes(), &bls_signature)
            } else {
                false
            }
        }
    }

    pub fn verify_aggregated_signature(signature: UInt768, public_keys: Vec<BLSKey>, messages: Vec<Vec<u8>>, use_legacy: bool) -> bool {
        let bls_public_keys = public_keys.iter().filter_map(|key| key.bls_public_key().ok()).collect::<Vec<_>>();
        let keys = bls_public_keys.iter().collect::<Vec<&G1Element>>();
        let messages = messages.iter().map(|m| m.as_slice()).collect::<Vec<_>>();
        let bytes = signature.as_bytes();
        if use_legacy {
            LegacySchemeMPL::new().aggregate_verify(keys, messages, &G2Element::from_bytes_legacy(bytes).unwrap())
        } else {
            BasicSchemeMPL::new().aggregate_verify(keys, messages, &G2Element::from_bytes(bytes).unwrap())
        }
    }
}

impl DHKey for BLSKey {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Option<Self> where Self: Sized {
        match (public_key.bls_public_key(), private_key.bls_private_key(), private_key.use_legacy) {
            (Ok(bls_public_key), Ok(bls_private_key), use_legacy) if public_key.use_legacy == use_legacy =>
                (bls_private_key * bls_public_key)
                    .ok()
                    .map(|key|
                        BLSKey::key_with_public_key(UInt384(if use_legacy { *key.serialize_legacy() } else { *key.serialize() }), use_legacy)),
            _ => None
        }
    }
}

impl CryptoData<BLSKey> for Vec<u8> {

    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &BLSKey, public_key: &BLSKey, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        secret_key.product(public_key)
            .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
            .and_then(|key_data: [u8; 32]| initialization_vector[..16].try_into().ok()
                .map(|iv_data: [u8; 16]| {
                    let mut destination = Vec::from(iv_data);
                    let config = cryptor::Config::AES256 {
                        mode: cryptor::Mode::CTR,
                        iv: Some(&iv_data),
                        key: &key_data,
                    };
                    let encrypted_data = <Self as CryptoData<BLSKey>>::encrypt(self, config).unwrap();
                    destination.extend(encrypted_data.clone());
                    destination
                }))
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &BLSKey, public_key: &BLSKey, iv_size: usize) -> Option<Vec<u8>> {
        if self.len() < iv_size {
            return None;
        }
        secret_key.product(public_key)
            .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
            .and_then(|key_data: [u8; 32]| self[..iv_size].try_into().ok()
                .and_then(|iv_data: [u8; 16]|
                    <Self as CryptoData<BLSKey>>::decrypt(self[iv_size..self.len()].to_vec(), cryptor::Config::AES256 {
                        mode: cryptor::Mode::CTR,
                        iv: Some(&iv_data),
                        key: &key_data,
                    })))
    }

    fn encrypt_with_dh_key_using_iv(&self, key: &BLSKey, initialization_vector: Vec<u8>) -> Option<Vec<u8>> {
        key.bls_public_key_serialized()
            .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
            .and_then(|key_data: [u8; 32]| initialization_vector[..16].try_into().ok()
                .and_then(|iv_data: [u8; 16]|
                    <Self as CryptoData<BLSKey>>::encrypt(self, cryptor::Config::AES256 {
                        mode: cryptor::Mode::CTR,
                        iv: Some(&iv_data),
                        key: &key_data,
                    })))
    }

    fn decrypt_with_dh_key_using_iv_size(&self, key: &BLSKey, iv_size: usize) -> Option<Vec<u8>> {
        if self.len() < iv_size {
            return None;
        }
        key.bls_public_key_serialized()
            .and_then(|sym_key_data| sym_key_data[..32].try_into().ok())
            .and_then(|key_data: [u8; 32]| self[..iv_size].try_into().ok()
                .and_then(|iv_data: [u8; 16]|
                    <Self as CryptoData<BLSKey>>::decrypt(self[iv_size..self.len()].to_vec(), cryptor::Config::AES256 {
                        mode: cryptor::Mode::CTR,
                        iv: Some(&iv_data),
                        key: &key_data,
                    })))
    }
}
