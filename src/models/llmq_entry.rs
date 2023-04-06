use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, TryRead, LE};
use hashes::hex::ToHex;
use std::convert::Into;
use bls_signatures::{BasicSchemeMPL, G1Element, G2Element, LegacySchemeMPL, Scheme};
use crate::common::llmq_version::LLMQVersion;
use crate::common::LLMQType;
use crate::consensus::encode::VarInt;
use crate::consensus::{Encodable, WriteExt};
use crate::crypto::data_ops::Data;
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::crypto::byte_util::AsBytes;
use crate::hashes::{sha256d, Hash};
use crate::models;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct LLMQEntry {
    pub version: LLMQVersion,
    pub llmq_hash: UInt256,
    pub index: Option<u16>,
    pub public_key: UInt384,
    pub threshold_signature: UInt768,
    pub verification_vector_hash: UInt256,
    pub all_commitment_aggregated_signature: UInt768,
    pub llmq_type: LLMQType,
    pub signers_bitset: Vec<u8>,
    pub signers_count: VarInt,
    pub valid_members_bitset: Vec<u8>,
    pub valid_members_count: VarInt,
    pub entry_hash: UInt256,
    pub verified: bool,
    pub saved: bool,
    pub commitment_hash: Option<UInt256>,
}
impl std::fmt::Debug for LLMQEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQEntry")
            .field("version", &self.version)
            .field("llmq_hash", &self.llmq_hash)
            .field("index", &self.index.unwrap_or(0))
            .field("public_key", &self.public_key)
            .field("threshold_signature", &self.threshold_signature)
            .field("verification_vector_hash", &self.verification_vector_hash)
            .field("all_commitment_aggregated_signature", &self.all_commitment_aggregated_signature)
            .field("llmq_type", &self.llmq_type)
            .field("signers_bitset", &self.signers_bitset.to_hex())
            .field("signers_bitset_length", &self.signers_bitset.len())
            .field("signers_count", &self.signers_count)
            .field("valid_members_bitset", &self.valid_members_bitset.to_hex())
            .field("valid_members_bitset_length", &self.valid_members_bitset.len())
            .field("valid_members_count", &self.valid_members_count)
            .field("entry_hash", &self.entry_hash)
            .field("verified", &self.verified)
            .field("commitment_hash", &self.commitment_hash)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for LLMQEntry {
    fn try_read(bytes: &'a [u8], _ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<LLMQVersion>(offset, LE)?;
        let llmq_type = bytes.read_with::<LLMQType>(offset, LE)?;
        let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?;

        let index = if version.use_rotated_quorums() {
            Some(bytes.read_with::<u16>(offset, LE)?)
        } else {
            None
        };
        let signers_count = bytes.read_with::<VarInt>(offset, LE)?;
        let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
        let signers_bitset: &[u8] = bytes.read_with(offset, Bytes::Len(signers_buffer_length))?;
        let valid_members_count = bytes.read_with::<VarInt>(offset, LE)?;
        let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
        let valid_members_bitset: &[u8] =
            bytes.read_with(offset, Bytes::Len(valid_members_count_buffer_length))?;
        let public_key = bytes.read_with::<UInt384>(offset, LE)?;
        let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?;
        let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?;
        let entry = LLMQEntry::new(
            version,
            llmq_type,
            llmq_hash,
            index,
            signers_count,
            valid_members_count,
            signers_bitset.to_vec(),
            valid_members_bitset.to_vec(),
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature
        );
        Ok((entry, *offset))
    }
}

impl LLMQEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: LLMQVersion,
        llmq_type: LLMQType,
        llmq_hash: UInt256,
        index: Option<u16>,
        signers_count: VarInt,
        valid_members_count: VarInt,
        signers_bitset: Vec<u8>,
        valid_members_bitset: Vec<u8>,
        public_key: UInt384,
        verification_vector_hash: UInt256,
        threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768,
    ) -> Self {
        let q_data = Self::generate_data(
            version,
            llmq_type,
            llmq_hash,
            index,
            signers_count,
            signers_bitset.as_slice(),
            valid_members_count,
            valid_members_bitset.as_slice(),
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature,
        );
        let entry_hash = UInt256(sha256d::Hash::hash(q_data.as_slice()).into_inner());
        //println!("LLMQEntry::new({}, {:?}, {}, {:?}, {}, {}, {}, {}, {}, {}, {}, {}) = {}", version, llmq_type, llmq_hash, index, signers_count, signers_bitset.to_hex(), valid_members_count, valid_members_bitset.to_hex(), public_key, verification_vector_hash, threshold_signature, all_commitment_aggregated_signature, entry_hash);
        Self {
            version,
            llmq_hash,
            index,
            public_key,
            threshold_signature,
            verification_vector_hash,
            all_commitment_aggregated_signature,
            llmq_type,
            signers_bitset,
            signers_count,
            valid_members_bitset,
            valid_members_count,
            entry_hash,
            verified: false,
            saved: false,
            commitment_hash: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_data(
        version: LLMQVersion,
        llmq_type: LLMQType,
        llmq_hash: UInt256,
        llmq_index: Option<u16>,
        signers_count: VarInt,
        signers_bitset: &[u8],
        valid_members_count: VarInt,
        valid_members_bitset: &[u8],
        public_key: UInt384,
        verification_vector_hash: UInt256,
        threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_u8: u8 = llmq_type.into();
        let llmq_v: u16 = version.into();
        *offset += llmq_v.consensus_encode(&mut buffer).unwrap();
        *offset += llmq_u8.consensus_encode(&mut buffer).unwrap();
        *offset += llmq_hash.consensus_encode(&mut buffer).unwrap();
        if let Some(index) = llmq_index {
            *offset += index.consensus_encode(&mut buffer).unwrap();
        }
        *offset += signers_count.consensus_encode(&mut buffer).unwrap();
        buffer.emit_slice(signers_bitset).unwrap();
        *offset += signers_bitset.len();
        *offset += valid_members_count.consensus_encode(&mut buffer).unwrap();
        buffer.emit_slice(valid_members_bitset).unwrap();
        *offset += valid_members_bitset.len();
        *offset += public_key.consensus_encode(&mut buffer).unwrap();
        *offset += verification_vector_hash
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += threshold_signature.consensus_encode(&mut buffer).unwrap();
        *offset += all_commitment_aggregated_signature
            .consensus_encode(&mut buffer)
            .unwrap();
        buffer
    }

    pub fn to_data(&self) -> Vec<u8> {
        Self::generate_data(
            self.version,
            self.llmq_type,
            self.llmq_hash,
            self.index,
            self.signers_count,
            &self.signers_bitset,
            self.valid_members_count,
            &self.valid_members_bitset,
            self.public_key,
            self.verification_vector_hash,
            self.threshold_signature,
            self.all_commitment_aggregated_signature,
        )
    }

    pub fn llmq_quorum_hash(&self) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(33);
        let offset: &mut usize = &mut 0;
        *offset += VarInt(self.llmq_type as u64)
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_type = VarInt(self.llmq_type as u64);
        *offset += llmq_type.consensus_encode(&mut buffer).unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        *offset += self
            .valid_members_count
            .consensus_encode(&mut buffer)
            .unwrap();
        buffer.emit_slice(&self.valid_members_bitset).unwrap();
        *offset += self.valid_members_bitset.len();
        *offset += self.public_key.consensus_encode(&mut buffer).unwrap();
        *offset += self
            .verification_vector_hash
            .consensus_encode(&mut buffer)
            .unwrap();
        buffer
    }

    pub fn ordering_hash_for_request_id(
        &self,
        request_id: UInt256,
        llmq_type: LLMQType,
    ) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_type = VarInt(llmq_type as u64);
        *offset += llmq_type.consensus_encode(&mut buffer).unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        *offset += request_id.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn generate_commitment_hash(&mut self) -> UInt256 {
        if self.commitment_hash.is_none() {
            let data = self.commitment_data();
            self.commitment_hash = Some(UInt256(sha256d::Hash::hash(&data).into_inner()));
        }
        self.commitment_hash.unwrap()
    }

    fn validate_bitset(bitset: Vec<u8>, count: VarInt) -> bool {
        if bitset.len() != (count.0 as usize + 7) / 8 {
            println!(
                "Error: The byte size of the bitvectors ({}) must match “(quorumSize + 7) / 8 ({})",
                bitset.len(),
                (count.0 + 7) / 8
            );
            return false;
        }
        let len = (bitset.len() * 8) as i32;
        let size = count.0 as i32;
        if len != size {
            let rem = len - size;
            let mask = !(0xff >> rem);
            let last_byte = match bitset.last() {
                Some(&last) => last as i32,
                None => 0,
            };
            if last_byte & mask != 0 {
                println!("Error: No out-of-range bits should be set in byte representation of the bitvector");
                return false;
            }
        }
        true
    }

    pub fn validate_payload(&self) -> bool {
        // The quorumHash must match the current DKG session
        // todo
        let is_valid_signers =
            Self::validate_bitset(self.signers_bitset.clone(), self.signers_count);
        if !is_valid_signers {
            println!(
                "Error: signers_bitset is invalid ({:?} {})",
                self.signers_bitset, self.signers_count
            );
            return false;
        }
        let is_valid_members =
            Self::validate_bitset(self.valid_members_bitset.clone(), self.valid_members_count);
        if !is_valid_members {
            println!(
                "Error: valid_members_bitset is invalid ({:?} {})",
                self.valid_members_bitset, self.valid_members_count
            );
            return false;
        }
        let quorum_threshold = self.llmq_type.threshold() as u64;
        // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
        let signers_bitset_true_bits_count = self.signers_bitset.as_slice().true_bits_count();
        if signers_bitset_true_bits_count < quorum_threshold {
            println!("Error: The number of set bits in the signers bitvector {} must be at least >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        let valid_members_bitset_true_bits_count =
            self.valid_members_bitset.as_slice().true_bits_count();
        if valid_members_bitset_true_bits_count < quorum_threshold {
            println!("Error: The number of set bits in the validMembers bitvector {} must be at least >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        true
    }
}

// TODO: combine with BLSKey
impl LLMQEntry {
    fn verify_secure_aggregated(message: &[u8], signature: &[u8], public_keys: Vec<G1Element>, use_legacy: bool) -> bool {
        let bls_signature = match if use_legacy {
            G2Element::from_bytes_legacy(signature)
        } else {
            G2Element::from_bytes(signature)
        } {
            Ok(signature) => signature,
            Err(err) => {
                println!("verify_secure_aggregated (legacy = {}): error: {}", use_legacy, err);
                return false;
            }
        };
        let keys = public_keys.iter().collect::<Vec<_>>();
        if use_legacy {
            LegacySchemeMPL::new().verify_secure(keys, message, &bls_signature)
        } else {
            BasicSchemeMPL::new().verify_secure(keys, message, &bls_signature)
        }
    }

    fn verify_quorum_signature(message: &[u8], threshold_signature: &[u8], public_key: &[u8], use_legacy: bool) -> bool {
        if use_legacy {
            LegacySchemeMPL::new()
                .verify(&G1Element::from_bytes_legacy(public_key).unwrap(), message, &G2Element::from_bytes_legacy(threshold_signature).unwrap())
        } else {
            BasicSchemeMPL::new()
                .verify(&G1Element::from_bytes(public_key).unwrap(), message, &G2Element::from_bytes(threshold_signature).unwrap())
        }
    }

    pub fn validate(&mut self, valid_masternodes: Vec<models::MasternodeEntry>, block_height: u32) -> bool {
        let commitment_hash = self.generate_commitment_hash();
        let use_legacy = self.version.use_bls_legacy();
        let operator_keys = (0..valid_masternodes.len()).into_iter().filter_map(|i| {
            match self.signers_bitset.as_slice().bit_is_true_at_le_index(i as u32) {
                true => {
                    let key = valid_masternodes[i].operator_public_key_at(block_height);
                    if key.version < 2 {
                        G1Element::from_bytes_legacy(key.data.as_bytes())
                    } else {
                        G1Element::from_bytes(key.data.as_bytes())
                    }.ok()
                },
                false => None
            }
        }).collect::<Vec<_>>();
        let all_commitment_aggregated_signature_validated = Self::verify_secure_aggregated(
            commitment_hash.as_bytes(),
            self.all_commitment_aggregated_signature.as_bytes(),
            operator_keys,
            use_legacy);
        if !all_commitment_aggregated_signature_validated {
            println!("••• Issue with all_commitment_aggregated_signature_validated: {}", self.all_commitment_aggregated_signature);
            return false;
        }
        // The sig must validate against the commitmentHash and all public keys determined by the signers bitvector.
        // This is an aggregated BLS signature verification.
        let quorum_signature_validated = Self::verify_quorum_signature(commitment_hash.as_bytes(), self.threshold_signature.as_bytes(), self.public_key.as_bytes(), use_legacy);
        if !quorum_signature_validated {
            println!("••• Issue with quorum_signature_validated");
            return false;
        }
        true
    }
}
