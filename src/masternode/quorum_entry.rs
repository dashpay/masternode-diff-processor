use std::convert::TryFrom;
use byte::{BytesExt, LE};
use crate::chain::chain::Chain;
use crate::common::llmq_type::LLMQType;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::Data;
use crate::crypto::data_ops::sha256_2;
use crate::keys::bls_key::BLSKey;
use crate::manager::BlockHeightLookup;
use crate::masternode::masternode_list::MasternodeList;
use crate::masternode_manager::BlockHeightLookup;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct QuorumEntry {
    pub version: u16,
    pub quorum_hash: [u8; 32],
    pub quorum_public_key: [u8; 48],
    pub quorum_threshold_signature: [u8; 96],
    pub quorum_verification_vector_hash: [u8; 32],
    pub all_commitment_aggregated_signature: [u8; 96],
    pub signers_count: VarInt,
    pub llmq_type: LLMQType,
    pub valid_members_count: VarInt,
    pub signers_bitset: [u8],
    pub valid_members_bitset: [u8],
    pub length: u32,
    pub quorum_entry_hash: [u8; 32],
    pub verified: bool,
    pub saved: bool,
    pub commitment_hash: Option<[u8; 32]>,
}

impl QuorumEntry {
    pub fn new(message: &[u8], mut data_offset: usize) -> Option<Self> {
        let length = message.length;
        let off = &mut data_offset;
        if length - off < 2 { return None; }
        let version = message.read_with::<u16>(off, LE)?;
        if length - off < 1 { return None; }
        let llmq_type = message.read_with::<u8>(off, LE)?;
        if length - off < 32 { return None; }
        let quorum_hash = message.read_with::<[u8; 32]>(off, LE)?;
        if length - off < 1 { return None; }
        let signers_count = VarInt(message.read_with::<u64>(off, LE)?);
        const SIGNERS_BUFFER_LENGTH: u16 = (signers_count + 7) / 8;
        if length - off < SIGNERS_BUFFER_LENGTH { return None; }
        let signers_bitset = message.read_with::<[u8; SIGNERS_BUFFER_LENGTH as usize]>(off, LE)? as [u8];
        if length - off < 1 { return None; }
        let valid_members_count = VarInt(message.read_with::<u64>(off, LE)?);
        const VALID_MEMBERS_COUNT_BUFFER_LENGTH: u16 = (valid_members_count + 7) / 8;
        if length - off < VALID_MEMBERS_COUNT_BUFFER_LENGTH { return None; }
        let valid_members_bitset = message.read_with::<[u8; VALID_MEMBERS_COUNT_BUFFER_LENGTH as usize]>(off, LE)? as [u8];
        if length - off < 48 { return None; }
        let quorum_public_key = message.read_with::<[u8; 48]>(off, LE)?;
        if length - off < 32 { return None; }
        let quorum_verification_vector_hash = message.read_with::<[u8; 32]>(off, LE)?;
        if length - off < 96 { return None; }
        let quorum_threshold_signature = message.read_with::<[u8; 96]>(off, LE)?;
        if length - off < 96 { return None; }
        let all_commitment_aggregated_signature = message.read_with::<[u8; 96]>(off, LE)?;
        let quorum_entry_hash = sha256_2(QuorumEntry::generate_data(
            version, llmq_type, quorum_hash, signers_count.clone(), &signers_bitset, quorum_public_key,
            quorum_verification_vector_hash, quorum_threshold_signature, all_commitment_aggregated_signature));
        Some(QuorumEntry {
            version,
            quorum_hash,
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            all_commitment_aggregated_signature,
            signers_count,
            llmq_type: LLMQType::try_from(llmq_type)?,
            valid_members_count,
            signers_bitset,
            valid_members_bitset,
            length: off - dataOffset,
            quorum_entry_hash,
            verified: false,
            saved: false,
            commitment_hash: None
        })
    }

    pub fn generate_data(
        version: u16,
        llmq_type: u8,
        quorum_hash: [u8; 32],
        signers_count: VarInt,
        signers_bitset: &[u8],
        quorum_public_key: [u8; 48],
        quorum_verification_vector_hash: [u8; 32],
        quorum_threshold_signature: [u8; 96],
        all_commitment_aggregated_signature: [u8; 96]
    ) -> &[u8] {
        let mut buffer = [0u8];
        let offset: &mut usize = &mut 0;
        buffer.write(offset, version);
        buffer.write(offset, llmq_type);
        buffer.write(offset, quorum_hash);
        buffer.write(offset, signers_count);
        buffer.write(offset, signers_bitset);
        buffer.write(offset, quorum_public_key);
        buffer.write(offset, quorum_verification_vector_hash);
        buffer.write(offset, quorum_threshold_signature);
        buffer.write(offset, all_commitment_aggregated_signature);
        &buffer
    }

    pub fn to_data(&self) -> &[u8] {
        let mut buffer = [0u8];
        let offset: &mut usize = &mut 0;
        buffer.write(offset, self.version);
        buffer.write(offset, self.llmq_type);
        buffer.write(offset, self.quorum_hash);
        buffer.write(offset, self.signers_count.clone());
        buffer.write(offset, self.signers_bitset);
        buffer.write(offset, self.quorum_public_key);
        buffer.write(offset, self.quorum_verification_vector_hash);
        buffer.write(offset, self.quorum_threshold_signature);
        buffer.write(offset, self.all_commitment_aggregated_signature);
        &buffer
    }

    pub fn quorum_threshold(&self) -> u32 {
        match self.llmq_type {
            LLMQType::LLMQType_50_60 => 30,
            LLMQType::LLMQType_400_60 => 240,
            LLMQType::LLMQType_400_85 => 340,
            LLMQType::LLMQType_100_67 => 67,
            LLMQType::LLMQType_5_60 => 3,
            LLMQType::LLMQType_10_60 => 6,
        }
    }
    pub fn quorum_size_for(llmq_type: LLMQType) -> u32 {
        match llmq_type {
            LLMQType::LLMQType_5_60 => 5,
            LLMQType::LLMQType_10_60 => 10,
            LLMQType::LLMQType_50_60 => 50,
            LLMQType::LLMQType_400_60 => 400,
            LLMQType::LLMQType_400_85 => 400,
            LLMQType::LLMQType_100_67 => 100,
        }
    }

    pub fn llmq_quorum_hash(&self) -> &[u8; 32] {
        let mut buffer = [0u8; 32];
        let offset: &mut usize = &mut 0;
        buffer.write(offset, self.llmq_type);
        buffer.write(offset, self.quorum_hash);
        &sha256_2(&buffer)
    }

    pub fn commitment_data(&self) -> &[u8] {
        let mut buffer = [0u8];
        let offset: &mut usize = &mut 0;
        buffer.write(offset, self.llmq_type);
        buffer.write(offset, self.quorum_hash);
        buffer.write(offset, self.valid_members_count.0);
        buffer.write(offset, self.valid_members_bitset);
        buffer.write(offset, self.quorum_public_key);
        buffer.write(offset, self.quorum_verification_vector_hash);
        &buffer
    }

    pub fn commitment_hash(&mut self) -> [u8; 32] {
        if self.commitment_hash.is_none() || self.commitment_hash?.is_empty() {
            self.commitment_hash = Some(sha256_2(self.commitment_data));
        }
        self.commitment_hash?
    }

    pub fn validate_with(&mut self, masternode_list: MasternodeList, block_height_lookup: BlockHeightLookup) -> bool {
        // The quorumHash must match the current DKG session
        // todo
        // The byte size of the signers and validMembers bitvectors must match “(quorumSize + 7) / 8”
        if self.signers_bitset.len() != (&self.signers_count + 7) / 8 {
            println!("Error: The byte size of the signers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})“", self.signers_bitset.len(), (self.signers_count.0 + 7) / 8);
            return false;
        }
        if self.valid_members_bitset.len() != (&self.valid_members_count + 7) / 8 {
            println!("Error: The byte size of the validMembers bitvectors ({}) must match “(quorumSize + 7) / 8 ({})", self.valid_members_bitset.len(), (self.valid_members_count.0 + 7) / 8);
            return false;
        }

        // No out-of-range bits should be set in byte representation of the signers and validMembers bitvectors
        let signers_offset: &mut usize = (self.signers_count.0 / 8) as &mut usize;
        let signers_last_byte = self.signers_bitset.read_with::<u8>(signers_offset, LE)?;
        let signers_mask = u8::MAX >> (8 - signers_offset) << (8 - signers_offset);
        if signers_last_byte & signers_mask {
            println!("Error: No out-of-range bits should be set in byte representation of the signers bitvector");
            return false;
        }

        let valid_members_offset: &mut usize = (self.valid_members_count.0 / 8) as &mut usize;
        let valid_members_last_byte: u8 = self.valid_members_bitset.read_with::<u8>(valid_members_offset, LE)?;
        let valid_members_mask = u8::MAX >> (8 - valid_members_offset) << (8 - valid_members_offset);
        if valid_members_last_byte & valid_members_mask {
            println!("Error: No out-of-range bits should be set in byte representation of the validMembers bitvector");
            return false;
        }
        let quorum_threshold = self.quorum_threshold() as u64;
        // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
        if self.signers_bitset.true_bits_count() < quorum_threshold {
            println!("Error: The number of set bits in the signers bitvector {} must be at least >= quorumThreshold {}", self.signers_bitset.true_bits_count(), quorum_threshold);
            return false;
        }
        if self.valid_members_bitset.true_bits_count() < quorum_threshold {
            println!("Error: The number of set bits in the validMembers bitvector {} must be at least >= quorumThreshold {}", self.valid_members_bitset.true_bits_count(), quorum_threshold);
            return false;
        }

        // The quorumSig must validate against the quorumPublicKey and the commitmentHash. As this is a recovered threshold signature, normal signature verification can be performed, without the need of the full quorum verification vector. The commitmentHash is calculated in the same way as in the commitment phase.

        const MASTERNODELIST_HEIGHT_TO_SAVE_DATA: u32 = 1377216;
        // let [DSQuorumEntry quorumSizeForType:self.llmqType]
        let quorum_count = QuorumEntry::quorum_size_for(self.llmq_type);
        let quorum_modifier = self.llmq_quorum_hash();
        let masternodes = masternode_list.valid_masternodes_for(quorum_modifier, quorum_count, block_height_lookup);
        let mut public_keys: Vec<BLSKey> = Vec::new();
        let mut i: u32 = 0;
        let block_height: u32 = block_height_lookup(masternode_list.block_hash);

        for masternode_entry in masternodes {
            if self.signers_bitset.bit_is_true_at_le_index(i) {
                let public_key = masternode_entry.operator_public_key_at(block_height);
                let key = BLSKey::key_with(public_key);
                public_keys.push(key);
            }
            i += 1;
        }
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
    }
}
