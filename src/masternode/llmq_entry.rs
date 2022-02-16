use std::convert::Into;
use byte::{BytesExt, LE, TryRead};
use byte::ctx::{Bytes, Endian};
use hashes::{Hash, sha256d};
use crate::common::llmq_type::LLMQType;
use crate::consensus::{Encodable, WriteExt};
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::{Data, UInt256, UInt384, UInt768};

pub const LLMQ_DEFAULT_VERSION: u16 = 1;
pub const LLMQ_INDEXED_VERSION: u16 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LLMQEntry<'a> {
    pub version: u16,
    pub llmq_hash: UInt256,
    pub index: Option<u32>,
    pub public_key: UInt384,
    pub threshold_signature: UInt768,
    pub verification_vector_hash: UInt256,
    pub all_commitment_aggregated_signature: UInt768,
    pub llmq_type: LLMQType,
    pub signers_bitset: &'a [u8],
    pub signers_count: VarInt,
    pub valid_members_bitset: &'a [u8],
    pub valid_members_count: VarInt,
    pub length: usize,
    pub entry_hash: UInt256,
    pub verified: bool,
    pub saved: bool,
    pub commitment_hash: Option<UInt256>,
}
impl<'a> std::fmt::Debug for LLMQEntry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQEntry")
            .field("entry_hash", &self.entry_hash)
            .field("signers_bitset", &self.signers_bitset)
            .field("signers_bitset_count", &self.signers_count.0)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for LLMQEntry<'a> {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<u16>(offset, LE)?;
        let llmq_type = bytes.read_with::<u8>(offset, LE)?;
        let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = match version {
            LLMQ_DEFAULT_VERSION => None,
            LLMQ_INDEXED_VERSION => {
                let index = bytes.read_with::<u32>(offset, LE)?;
                Some(index)
            } ,
            _ => None,
        };
        let signers_count = bytes.read_with::<VarInt>(offset, LE)?;
        let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
        let signers_bitset: &[u8] = bytes.read_with(offset, Bytes::Len(signers_buffer_length))?;
        let valid_members_count = bytes.read_with::<VarInt>(offset, LE)?;
        let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
        let valid_members_bitset: &[u8] = bytes.read_with(offset, Bytes::Len(valid_members_count_buffer_length))?;

        let public_key = bytes.read_with::<UInt384>(offset, LE)?;
        let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?;
        let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?;
        let llmq_type: LLMQType = llmq_type.into();

        let q_data = &LLMQEntry::generate_data(
            version, llmq_type, llmq_hash,
            signers_count.clone(), &signers_bitset,
            valid_members_count.clone(), &valid_members_bitset,
            public_key, verification_vector_hash, threshold_signature,
            all_commitment_aggregated_signature);
        let entry_hash = UInt256(sha256d::Hash::hash(q_data).into_inner());

        Ok((LLMQEntry {
            version,
            llmq_hash,
            index,
            public_key,
            threshold_signature,
            verification_vector_hash,
            all_commitment_aggregated_signature,
            signers_count,
            llmq_type,
            valid_members_count,
            signers_bitset,
            valid_members_bitset,
            length: *offset,
            entry_hash,
            verified: false,
            saved: false,
            commitment_hash: None
        }, *offset))
    }
}

impl<'a> LLMQEntry<'a> {

    pub fn generate_data(
        version: u16,
        llmq_type: LLMQType,
        llmq_hash: UInt256,
        signers_count: VarInt,
        signers_bitset: &[u8],
        valid_members_count: VarInt,
        valid_members_bitset: &[u8],
        public_key: UInt384,
        verification_vector_hash: UInt256,
        threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_u8: u8 = llmq_type.into();
        *offset += version.consensus_encode(&mut buffer).unwrap();
        *offset += llmq_u8.consensus_encode(&mut buffer).unwrap();
        *offset += llmq_hash.consensus_encode(&mut buffer).unwrap();
        *offset += signers_count.consensus_encode(&mut buffer).unwrap();
        buffer.emit_slice(&signers_bitset).unwrap();
        *offset += signers_bitset.len();
        *offset += valid_members_count.consensus_encode(&mut buffer).unwrap();
        buffer.emit_slice(&valid_members_bitset).unwrap();
        *offset += valid_members_bitset.len();
        *offset += public_key.consensus_encode(&mut buffer).unwrap();
        *offset += verification_vector_hash.consensus_encode(&mut buffer).unwrap();
        *offset += threshold_signature.consensus_encode(&mut buffer).unwrap();
        *offset += all_commitment_aggregated_signature.consensus_encode(&mut buffer).unwrap();
        buffer
    }

    pub fn to_data(&self) -> Vec<u8> {
        LLMQEntry::generate_data(
            self.version, self.llmq_type, self.llmq_hash,
            self.signers_count, self.signers_bitset,
            self.valid_members_count, self.valid_members_bitset,
            self.public_key, self.verification_vector_hash,
            self.threshold_signature, self.all_commitment_aggregated_signature)
    }

    pub fn llmq_quorum_hash(&self) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(33);
        let offset: &mut usize = &mut 0;
        *offset += VarInt(self.llmq_type as u64).consensus_encode(&mut buffer).unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_type = VarInt(self.llmq_type as u64);
        *offset += llmq_type.consensus_encode(&mut buffer).unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        *offset += self.valid_members_count.consensus_encode(&mut buffer).unwrap();
        buffer.emit_slice(&self.valid_members_bitset).unwrap();
        *offset += self.valid_members_bitset.len();
        *offset += self.public_key.consensus_encode(&mut buffer).unwrap();
        *offset += self.verification_vector_hash.consensus_encode(&mut buffer).unwrap();
        buffer
    }

    pub fn generate_commitment_hash(&mut self) -> UInt256 {
        if self.commitment_hash.is_none() {
            let data = self.commitment_data();
            self.commitment_hash = Some(UInt256(sha256d::Hash::hash(&data).into_inner()));
        }
        self.commitment_hash.unwrap()
    }

    pub fn validate_payload(&self) -> bool {
        // The quorumHash must match the current DKG session
        // todo
        // The byte size of the signers and validMembers bitvectors must match “(quorumSize + 7) / 8”
        if self.signers_bitset.len() != (self.signers_count.0 as usize + 7) / 8 {
            println!("Error: The byte size of the signers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})“", self.signers_bitset.len(), (self.signers_count.0 + 7) / 8);
            return false;
        }
        if self.valid_members_bitset.len() != (self.valid_members_count.0 as usize + 7) / 8 {
            println!("Error: The byte size of the validMembers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", self.valid_members_bitset.len(), (self.valid_members_count.0 + 7) / 8);
            return false;
        }
        let signers_offset: usize = (self.signers_count.0 as usize) / 8;
        let signers_last_byte = match self.signers_bitset.read_with::<u8>(&mut signers_offset.clone(), LE) {
            Ok(data) => data,
            Err(_err) => 0
        };
        let signers_mask = if signers_offset > 0 && signers_offset <= 8 { u8::MAX >> (8 - signers_offset) << (8 - signers_offset) } else { 0 };
        let signers_byte_and_mask = signers_last_byte & signers_mask;
        if signers_byte_and_mask != 0 {
            println!("Error: No out-of-range bits should be set in byte representation of the signers bitvector");
            return false;
        }
        let valid_members_offset = (self.valid_members_count.0 as usize) / 8;
        // thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value: BadOffset(50)', src/masternode/llmq_entry:216:116
        let valid_members_last_byte = match self.valid_members_bitset.read_with::<u8>(&mut valid_members_offset.clone(), LE) {
            Ok(data) => data,
            Err(_err) => 0
        };
        let valid_members_mask = if valid_members_offset > 0 && valid_members_offset <= 8 { u8::MAX >> (8 - valid_members_offset) << (8 - valid_members_offset) } else { 0 };
        let valid_members_byte_and_mask = valid_members_last_byte & valid_members_mask;
        if valid_members_byte_and_mask != 0 {
            println!("Error: No out-of-range bits should be set in byte representation of the validMembers bitvector");
            return false;
        }
        let quorum_threshold = self.llmq_type.threshold() as u64;
        // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
        let signers_bitset_true_bits_count = self.signers_bitset.true_bits_count();
        if signers_bitset_true_bits_count < quorum_threshold {
            println!("Error: The number of set bits in the signers bitvector {} must be at least >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        let valid_members_bitset_true_bits_count = self.valid_members_bitset.true_bits_count();
        if valid_members_bitset_true_bits_count < quorum_threshold {
            println!("Error: The number of set bits in the validMembers bitvector {} must be at least >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        true
    }
}
