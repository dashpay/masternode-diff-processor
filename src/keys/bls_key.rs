/*use secrets::traits::AsContiguousBytes;
use crate::crypto::byte_util::{UInt256, UInt384, UInt768};
use crate::hashes::sha256d;
use crate::keys::key::Key;

#[derive(Debug)]
pub struct BLSKey<'a> {
    pub base: Option<Key<'a>>,
    pub chain_code: Option<UInt256>,
    pub secret_key: Option<UInt256>,
    pub public_key: UInt384,
}

impl BLSKey<'static> {
    pub fn with(public_key: UInt384) -> Self {
        Self {
            base: None,
            chain_code: None,
            secret_key: None,
            public_key
        }
    }
    pub fn bls_private_key(&self) -> bls::PrivateKey {
        if self.secret_key.is_some() && !self.secret_key?.0.is_empty() ||
            self.base.is_none() ||
            self.base.unwrap().extended_private_key_data.len() == 0 {
            bls::PrivateKey::FromBytes(self.secret_key?.0.as_bytes())
        } else {
            bls::ExtendedPrivateKey::FromBytes(self.base?.extended_private_key_data)
        }
    }

    pub fn bls_public_key(&self) -> bls::PublicKey {
        if self.public_key.0.is_empty() {
            self.bls_private_key().GetPublicKey()
        } else {
            bls::PublicKey::FromBytes(self.public_key.0.as_bytes())
        }
    }

    pub fn public_key_fingerprint(&self) -> u32 {
        bls::PublicKey::FromBytes(
            self.public_key.0.as_bytes())
            .GetFingerprint()
    }

    pub fn verify(message_digest: sha256d::Hash, signature: UInt768, public_key: UInt384) -> bool {
        bls::Signature::FromBytes(
            signature.0.as_bytes(),
            bls::AggregationInfo::FromMsgHash(
                BLSKey::with(public_key).bls_public_key(),
                message_digest.as_bytes()))
            .Verify()
    }


    pub fn verify_secure_aggregated(message_digest: sha256d::Hash, signature: UInt768, public_keys:Vec<BLSKey>) -> bool {
        let infos: Vec<bls::AggregationInfo> = Vec::new();
        for key in public_keys {
            infos.push_back(bls::AggregationInfo::FromMsgHash(key.bls_public_key(), message_digest.as_bytes()));
        }
        bls::Signature::FromBytes(
            signature.0.as_bytes(),
            bls::AggregationInfo::MergeInfos(infos))
            .Verify()
    }

}

 */
