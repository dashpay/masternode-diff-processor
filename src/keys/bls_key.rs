use bls_signatures::bip32::{ExtendedPrivateKey, ExtendedPublicKey};
use bls_signatures::{BasicSchemeMPL, BlsError, G1Element, G2Element, LegacySchemeMPL, PrivateKey, Scheme};
use hashes::{Hash, sha256, sha256d};
use hashes::hex::{FromHex, ToHex};
use crate::chain::{derivation::IIndexPath, ScriptMap};
use crate::consensus::Encodable;
use crate::crypto::{UInt256, UInt384, UInt768, byte_util::{AsBytes, BytesDecodable, Zeroable}, UInt160};
use crate::keys::{IKey, KeyType, dip14::{IChildKeyDerivation, SignKey}};
use crate::util::{base58, data_ops::hex_with_data};
use crate::util::sec_vec::SecVec;

#[derive(Clone, Debug, Default)]
pub struct BLSKey {
    pub seckey: UInt256,
    pub chaincode: UInt256,
    pub pubkey: UInt384,
    pub extended_private_key_data: SecVec,
    pub extended_public_key_data: Vec<u8>,
    pub use_legacy: bool,
}

impl BLSKey {

    pub fn key_with_secret_hex(string: &str, use_legacy: bool) -> Option<Self> {
        Vec::from_hex(string)
            .ok()
            .map(|data| Self::key_with_seed_data(&data, use_legacy))
    }
    pub fn key_with_private_key(string: &str, use_legacy: bool) -> Option<Self> {
        Vec::from_hex(string.as_bytes().to_hex().as_str())
            .ok()
            .and_then(|data| Self::key_with_private_key_data(&data, use_legacy))
    }

    pub fn key_with_private_key_data(data: &Vec<u8>, use_legacy: bool) -> Option<Self> {
        UInt256::from_bytes(data, &mut 0)
            .and_then(|seckey| PrivateKey::from_bytes(data, false)
                .ok()
                .and_then(|bls_private_key| bls_private_key.g1_element()
                    .ok()
                    .map(|bls_public_key|
                        Self {
                            seckey,
                            pubkey: UInt384(*if use_legacy { bls_public_key.serialize() } else { bls_public_key.serialize_legacy() }),
                            use_legacy,
                            ..Default::default() })))
    }

    pub fn key_with_public_key(pubkey: UInt384, use_legacy: bool) -> Self {
        Self { pubkey, use_legacy, ..Default::default() }
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
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.sign_digest(UInt256::from(data)).as_bytes().to_vec()
    }
    fn verify(&mut self, message_digest: &[u8], signature: &[u8]) -> bool {
        self.verify_uint768(UInt256::from(message_digest), UInt768::from(signature))
    }

    fn secret_key(&self) -> UInt256 {
        self.seckey
    }

    fn chaincode(&self) -> UInt256 {
        self.chaincode
    }

    fn fingerprint(&self) -> u32 {
        self.public_key_fingerprint()
    }

    fn private_key_data(&self) -> Option<Vec<u8>> where Self: Sized {
        (!self.seckey.is_zero())
            .then_some(self.seckey.0.to_vec())
    }

    fn public_key_data(&self) -> Vec<u8> {
        self.pubkey.0.to_vec()
    }

    fn extended_private_key_data(&self) -> Option<SecVec> {
        Some(self.extended_private_key_data.clone())
    }

    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        Some(self.extended_public_key_data.clone())
    }

    fn private_derive_to_path2<SK, PK, PATH, INDEX>(&self, path: &PATH) -> Option<Self>
        where Self: Sized + IChildKeyDerivation<INDEX, SK, PK>,
              PATH: IIndexPath<Item=INDEX>, SK: SignKey {
        todo!()
    }

    fn private_derive_to_path<PATH>(&self, path: &PATH) -> Option<Self>
        where Self: Sized, PATH: IIndexPath<Item = u32> {
        ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_slice())
            .ok()
            .and_then(|bls_extended_private_key|
                Self::init_with_bls_extended_private_key(&Self::derive(bls_extended_private_key, path, self.use_legacy), self.use_legacy))
    }

    fn serialized_private_key_for_script(&self, script: &ScriptMap) -> String {
        // if (uint256_is_zero(self.secretKey)) return nil;
        // NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
        let mut writer = SecVec::with_capacity(34);
        script.privkey.enc(&mut writer);
        self.seckey.enc(&mut writer);
        b'\x02'.enc(&mut writer);
        base58::check_encode_slice(&writer)
    }

    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        UInt256::hmac::<sha256::Hash>(self.seckey.as_bytes(), data)

    }

    fn forget_private_key(&mut self) {
        self.seckey = UInt256::MIN;
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
    pub fn derive<PATH>(extended_private_key: ExtendedPrivateKey, path: &PATH, use_legacy: bool) -> ExtendedPrivateKey
        where PATH: IIndexPath<Item = u32> {
        if path.is_empty() {
            extended_private_key
        } else {
            let top_index_path = path.index_at_position(0);
            let sk_child = if use_legacy {
                extended_private_key.private_child_legacy(top_index_path)
            } else {
                extended_private_key.private_child(top_index_path)
            };
            Self::derive(sk_child, &path.index_path_by_removing_first_index(), use_legacy)
        }
    }

    // pub fn can_public_derive(index_path: IndexPath<u32>, use_legacy: bool) -> bool {
    //     for i in 0..index_path.length() {
    //         if index_path.index_at_position(0) >> 31 == 1 {
    //             return false;
    //         }
    //     }
    //     true
    // }

    pub fn public_derive<PATH>(extended_public_key: ExtendedPublicKey, index_path: &PATH, use_legacy: bool) -> ExtendedPublicKey
        where PATH: IIndexPath<Item = u32> {
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

    pub fn key_with_seed_data(seed: &Vec<u8>, use_legacy: bool) -> Self {
        let bls_private_key = PrivateKey::from_bip32_seed(seed);
        let bls_public_key = bls_private_key.g1_element().unwrap();
        let seckey = UInt256::from(&*bls_private_key.serialize());
        let pubkey = UInt384(*if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        });
        Self { seckey, pubkey, use_legacy, ..Default::default() }
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
            extended_private_key_data: SecVec::new(),
            extended_public_key_data,
            chaincode: UInt256(*bls_extended_public_key.chain_code().serialize()),
            seckey: UInt256::MIN,
            pubkey: UInt384(*public_key_data),
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
        let chaincode = UInt256(*bls_extended_private_key.chain_code().serialize());
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
        if let Some(seckey) = UInt256::from_bytes(bls_private_key.serialize().as_slice(), &mut 0) {
            Some(Self {
                extended_private_key_data: SecVec::with_vec(extended_private_key_data.to_vec()),
                extended_public_key_data: extended_public_key_data.to_vec(),
                chaincode,
                seckey,
                pubkey: UInt384(*bls_public_key_bytes),
                use_legacy,
            })
        } else {
            println!("Can't restore secret_key");
            return None;
        }
    }

    pub fn extended_private_key_with_seed_data(seed: &[u8], use_legacy: bool) -> Option<Self> {
        ExtendedPrivateKey::from_seed(seed)
            .ok()
            .and_then(|pk| Self::init_with_bls_extended_private_key(&pk, use_legacy))
    }


    pub fn public_key_from_extended_public_key_data<PATH>(data: &[u8], index_path: &PATH, use_legacy: bool) -> Option<Vec<u8>>
        where PATH: IIndexPath<Item = u32> {
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
            G1Element::from_bytes_legacy(self.pubkey.as_bytes()).unwrap().fingerprint_legacy()
        } else {
            G1Element::from_bytes(self.pubkey.as_bytes()).unwrap().fingerprint()
        }
    }

    pub fn secret_key_string(&self) -> String {
        if self.seckey.is_zero() {
            String::new()
        } else {
            hex_with_data(self.seckey.as_bytes())
        }
    }

    pub fn serialized_private_key_for_script_map(&self, map: &ScriptMap) -> Option<String> {
        if self.seckey.is_zero() {
            None
        } else {
            // todo: impl securebox here
            let mut writer = Vec::<u8>::with_capacity(34);
            map.privkey.enc(&mut writer);
            self.seckey.enc(&mut writer);
            b'\x02'.enc(&mut writer);
            Some(base58::check_encode_slice(&writer))
        }
    }

    pub fn public_derive_to_path<PATH>(&mut self, index_path: &PATH) -> Option<Self>
        where PATH: IIndexPath<Item = u32> {
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
        if !self.seckey.is_zero() {
            PrivateKey::from_bytes(self.seckey.as_bytes(), true)
        } else {
            ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_slice()).map(|ext_pk| ext_pk.private_key())
        }
    }

    pub(crate) fn bls_public_key(&self) -> Result<G1Element, BlsError> {
        if self.pubkey.is_zero() {
            self.bls_private_key().and_then(|bls_pk| bls_pk.g1_element())
        } else if self.use_legacy {
            G1Element::from_bytes_legacy(self.pubkey.as_bytes())
        } else {
            G1Element::from_bytes(self.pubkey.as_bytes())
        }
    }

    pub(crate) fn bls_public_key_serialized(&self) -> Option<[u8; 48]> {
        self.bls_public_key()
            .ok()
            .map(|pk| if self.use_legacy { *pk.serialize_legacy() } else { *pk.serialize() })
    }

    /// Signing
    pub fn sign_data(&self, data: &[u8]) -> UInt768 {
        if self.seckey.is_zero() && self.extended_private_key_data.is_empty() {
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
        if self.seckey.is_zero() && self.extended_private_key_data.is_empty() {
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
        if self.seckey.is_zero() && self.extended_private_key_data.is_empty() {
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

/// For FFI
impl BLSKey {
    pub fn public_key_from_extended_public_key_data_at_index_path<PATH>(key: &Self, index_path: &PATH) -> Option<Self> where Self: Sized, PATH: IIndexPath<Item=u32> {
        key.extended_public_key_data()
            .and_then(|ext_pk_data| Self::public_key_from_extended_public_key_data(&ext_pk_data, index_path, key.use_legacy))
            .map(|pub_key_data| Self::key_with_public_key(UInt384::from(pub_key_data), key.use_legacy))
    }

    pub fn key_with_extended_public_key_data(bytes: &[u8], use_legacy: bool) -> Option<Self> {
        if use_legacy {
            ExtendedPublicKey::from_bytes_legacy(bytes)
        } else {
            ExtendedPublicKey::from_bytes(bytes)
        }.ok().map(|bls_extended_public_key| Self::init_with_bls_extended_public_key(&bls_extended_public_key, use_legacy))

    }

    pub fn key_with_extended_private_key_data(bytes: &[u8], use_legacy: bool) -> Option<Self> {
        ExtendedPrivateKey::from_bytes(bytes)
            .ok()
            .and_then(|pk| Self::init_with_bls_extended_private_key(&pk, use_legacy))

    }

    pub fn has_private_key(&self) -> bool {
        !self.seckey.is_zero()
    }

    pub fn hash160(&self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
    }

}
