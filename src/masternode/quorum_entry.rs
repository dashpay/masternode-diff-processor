use std::convert::Into;
use byte::{BytesExt, LE};
use byte::ctx::Bytes;
use hashes::{Hash, sha256d};
use secrets::traits::AsContiguousBytes;
use crate::common::llmq_type::LLMQType;
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::{Data, UInt256, UInt384, UInt768};
// use crate::keys::bls_key::BLSKey;
use crate::manager::BlockHeightLookup;
use crate::masternode::masternode_list::MasternodeList;

// #[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct QuorumEntry<'a> {
    pub version: u16,
    pub quorum_hash: UInt256,
    pub quorum_public_key: UInt384,
    pub quorum_threshold_signature: UInt768,
    pub quorum_verification_vector_hash: UInt256,
    pub all_commitment_aggregated_signature: UInt768,
    pub signers_count: VarInt,
    pub llmq_type: LLMQType,
    pub valid_members_count: VarInt,
    pub signers_bitset: &'a [u8],
    pub valid_members_bitset: &'a [u8],
    pub length: usize,
    pub quorum_entry_hash: sha256d::Hash,
    pub verified: bool,
    pub saved: bool,
    pub commitment_hash: Option<sha256d::Hash>,
}

impl<'a> QuorumEntry<'a> {
    pub fn new(message: &'a [u8], data_offset: usize) -> Option<Self> {
        let length = message.len();
        let offset = &mut data_offset.clone();
        let version = match message.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            _ => { return None; }
        };
        let llmq_type = match message.read_with::<u8>(offset, LE) {
            Ok(data) => data,
            _ => { return None; }
        };
        let quorum_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            _ => { return None; }
        };

        let signers_count = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += signers_count.len();

        let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
        if length - *offset < signers_buffer_length { return None; }
        let signers_bitset: &[u8] = message.read_with(offset, Bytes::Len(signers_buffer_length)).unwrap();
        //*offset += signers_buffer_length;

        let valid_members_count = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += valid_members_count.len();

        let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
        if length - *offset < valid_members_count_buffer_length { return None; }
        let valid_members_bitset: &[u8] = message.read_with(offset, Bytes::Len(valid_members_count_buffer_length)).unwrap();
        //*offset += valid_members_count_buffer_length;

        let quorum_public_key = match message.read_with::<UInt384>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let quorum_verification_vector_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let quorum_threshold_signature = match message.read_with::<UInt768>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let all_commitment_aggregated_signature = match message.read_with::<UInt768>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };


        let llmq_type: LLMQType = llmq_type.into();
        let quorum_entry_hash = sha256d::Hash::hash(QuorumEntry::generate_data(
            version, llmq_type, quorum_hash, signers_count.clone(), &signers_bitset, quorum_public_key,
            quorum_verification_vector_hash, quorum_threshold_signature, all_commitment_aggregated_signature));
        let length = *offset - data_offset;
        //LLMQType::try_from(llmq_type)
        Some(QuorumEntry {
            version,
            quorum_hash,
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            all_commitment_aggregated_signature,
            signers_count: signers_count.clone(),
            llmq_type,
            valid_members_count: valid_members_count.clone(),
            signers_bitset,
            valid_members_bitset,
            length,
            quorum_entry_hash,
            verified: false,
            saved: false,
            commitment_hash: None
        })
    }

    pub fn generate_data(
        version: u16,
        llmq_type: LLMQType,
        quorum_hash: UInt256,
        signers_count: VarInt,
        signers_bitset: &[u8],
        quorum_public_key: UInt384,
        quorum_verification_vector_hash: UInt256,
        quorum_threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768
    ) -> &[u8] {
        let buffer: &mut [u8] = &mut [];
        let offset: &mut usize = &mut 0;
        let llmq_u8: u8 = llmq_type.into();
        buffer.write(offset, version);
        buffer.write(offset, llmq_u8);
        buffer.write(offset, quorum_hash);
        let mut signers_count_buffer = [0u8];
        *offset += signers_count.consensus_encode(&mut signers_count_buffer.as_mut_bytes()).unwrap_or(0);
        buffer.write(offset, signers_count_buffer.as_bytes());
        buffer.write(offset, signers_bitset);
        buffer.write(offset, quorum_public_key);
        buffer.write(offset, quorum_verification_vector_hash);
        buffer.write(offset, quorum_threshold_signature);
        buffer.write(offset, all_commitment_aggregated_signature);
        buffer
    }

    pub fn to_data(&self) -> &[u8] {
        QuorumEntry::generate_data(
            self.version, self.llmq_type, self.quorum_hash,
            self.signers_count, self.signers_bitset,
            self.quorum_public_key, self.quorum_verification_vector_hash,
            self.quorum_threshold_signature, self.all_commitment_aggregated_signature)
    }

    pub fn llmq_quorum_hash(&self) -> UInt256 {
        let mut buffer = [0u8; 33];
        let offset: &mut usize = &mut 0;
        let llmq_u8: u8 = self.llmq_type.into();
        buffer.write(offset, llmq_u8);
        buffer.write(offset, self.quorum_hash);
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn commitment_data(&self) -> &[u8] {
        let buffer: &mut [u8] = &mut [];
        let offset: &mut usize = &mut 0;
        let llmq_u8: u8 = self.llmq_type.into();
        buffer.write(offset, llmq_u8);
        buffer.write(offset, self.quorum_hash);
        let mut valid_members_count_buffer = [0u8];
        match self.valid_members_count.consensus_encode(&mut valid_members_count_buffer.as_mut_bytes()) {
            Ok(size) => size,
            _ => 0
        };
        buffer.write(offset, valid_members_count_buffer.as_bytes());
        buffer.write(offset, self.valid_members_bitset);
        buffer.write(offset, self.quorum_public_key);
        buffer.write(offset, self.quorum_verification_vector_hash);
        buffer
    }

    pub fn commitment_hash(&mut self) -> sha256d::Hash {
        if self.commitment_hash.is_none() ||
            self.commitment_hash.unwrap().is_empty() {
            self.commitment_hash = Some(sha256d::Hash::hash(self.commitment_data()));
        }
        self.commitment_hash.unwrap()
    }

    pub fn validate_payload(&mut self) -> bool {
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

        // No out-of-range bits should be set in byte representation of the signers and validMembers bitvectors
        let mut signers_offset: usize = (self.signers_count.0 as usize) / 8;
        let signers_last_byte = match self.signers_bitset.read_with::<u8>(&mut signers_offset, LE) {
            Ok(data) => data,
            Err(_err) => 0
        };
        let signers_mask = u8::MAX >> (8 - signers_offset) << (8 - signers_offset);
        if signers_last_byte & signers_mask != 0 {
            println!("Error: No out-of-range bits should be set in byte representation of the signers bitvector");
            return false;
        }

        let mut valid_members_offset = self.valid_members_count.0 as usize / 8;
        let valid_members_last_byte: u8 = self.valid_members_bitset.read_with::<u8>(&mut valid_members_offset, LE).unwrap();
        let valid_members_mask = u8::MAX >> (8 - valid_members_offset) << (8 - valid_members_offset);
        if valid_members_last_byte & valid_members_mask != 0 {
            println!("Error: No out-of-range bits should be set in byte representation of the validMembers bitvector");
            return false;
        }
        let quorum_threshold = self.llmq_type.quorum_threshold();
        // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
        if self.signers_bitset.true_bits_count() < quorum_threshold as u64 {
            println!("Error: The number of set bits in the signers bitvector {} must be at least >= quorumThreshold {}", self.signers_bitset.true_bits_count(), quorum_threshold);
            return false;
        }
        if self.valid_members_bitset.true_bits_count() < quorum_threshold as u64 {
            println!("Error: The number of set bits in the validMembers bitvector {} must be at least >= quorumThreshold {}", self.valid_members_bitset.true_bits_count(), quorum_threshold);
            return false;
        }
        true
    }

    pub fn get_operator_public_keys(&self, masternode_list: MasternodeList<'static>, block_height_lookup: BlockHeightLookup) -> Vec<UInt384> {
        const MASTERNODELIST_HEIGHT_TO_SAVE_DATA: u32 = 1377216;
        let quorum_count = self.llmq_type.quorum_size();
        let quorum_modifier = self.llmq_quorum_hash();
        let masternodes = masternode_list.valid_masternodes_for(quorum_modifier, quorum_count, block_height_lookup);
        let mut public_keys: Vec<UInt384> = Vec::new();
        let mut i: u32 = 0;
        let block_height: u32 = unsafe { block_height_lookup(masternode_list.block_hash.0.as_ptr()) };
        for masternode_entry in masternodes {
            if self.signers_bitset.bit_is_true_at_le_index(i) {
                public_keys.push(masternode_entry.operator_public_key_at(block_height));
            }
            i += 1;
        }
        public_keys
    }

    // The quorumSig must validate against the quorumPublicKey and the commitmentHash. As this is a recovered threshold signature, normal signature verification can be performed, without the need of the full quorum verification vector. The commitmentHash is calculated in the same way as in the commitment phase.
    /*pub fn validate_signatures(&mut self) -> bool {
        let all_commitment_aggregated_signature_validated = BLSKey::verify_secure_aggregated(self.commitment_hash(), self.all_commitment_aggregated_signature, public_keys);
        if !all_commitment_aggregated_signature_validated {
            return false;
        }
        // The sig must validate against the commitmentHash and all public keys determined by the
        // signers bitvector. This is an aggregated BLS signature verification.
        if BLSKey::verify(self.commitment_hash(), self.quorum_threshold_signature, self.quorum_public_key) {
            self.verified = true;
            true
        } else {
            println!("Issue with quorumSignatureValidated");
            false
        }
    }*/
}
