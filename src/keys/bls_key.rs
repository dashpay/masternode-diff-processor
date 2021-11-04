use secrets::traits::AsContiguousBytes;
use bls_signatures::PrivateKey;
use crate::keys::key::Key;
// use signature_bls::{AggregateSignature, PublicKey};
#[repr(C)]
#[derive(Debug)]
pub struct BLSKey<'a> {
    pub base: Option<Key<'a>>,
    pub chain_code: Option<[u8; 32]>,
    pub secret_key: Option<[u8; 32]>,
    pub public_key: &'a [u8; 48],
}

impl BLSKey {
    pub fn key_with(public_key: &[u8; 48]) -> Self {
        Self {
            base: None,
            chain_code: None,
            secret_key: None,
            public_key
        }
    }
    pub fn bls_private_key(&self) -> bls::PrivateKey {
        if self.secret_key.is_some() && !self.secret_key?.is_empty() ||
            self.base.is_none() ||
            self.base?.extended_private_key_data.len() == 0 {
            bls::PrivateKey::FromBytes(self.secret_key?.as_bytes())
        } else {
            bls::ExtendedPrivateKey::FromBytes(self.base?.extended_private_key_data)
        }
    }

    pub fn bls_public_key(&self) -> signature_bls::PublicKey {
        if self.public_key.is_empty() {
            self.bls_private_key().GetPublicKey()
        } else {
            bls::PublicKey::FromBytes(self.public_key.as_bytes())
        }
    }

    pub fn public_key_fingerprint(&self) -> u32 {
        bls::PublicKey::FromBytes(
            self.public_key.as_bytes())
            .GetFingerprint()
    }

    pub fn verify(message_digest: [u8; 32], signature: [u8; 96], public_key:[u8; 48]) -> bool {
        bls::Signature::FromBytes(
            signature.as_bytes(),
            bls::AggregationInfo::FromMsgHash(
                BLSKey::key_with(&public_key).bls_public_key(),
                message_digest.as_bytes()))
            .Verify()
    }


    pub fn verify_secure_aggregated(message_digest: [u8; 32], signature: [u8; 96], public_keys:Vec<BLSKey>) -> bool {
        let infos: Vec<bls::AggregationInfo> = Vec::new();
        for key in public_keys {
            infos.push_back(bls::AggregationInfo::FromMsgHash(key.bls_public_key(), message_digest.as_bytes()));
        }
        bls::Signature::FromBytes(
            signature.as_bytes(),
            bls::AggregationInfo::MergeInfos(infos))
            .Verify()
    }

}
