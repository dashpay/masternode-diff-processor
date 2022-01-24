use std::ffi::c_void;
use std::ptr::null_mut;
use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use crate::common::llmq_type::LLMQType;
use crate::{boxed, boxed_vec, UInt256};
use crate::consensus::Decodable;
use crate::crypto::byte_util::{data_at_offset_from, UInt128, UInt160, UInt384, UInt768};
use crate::processing::quorum_snapshot::QuorumSnapshotSkipMode;
use crate::transactions::transaction::{TransactionType, TX_UNCONFIRMED};

/// This types reflected for FFI

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeList {
    pub block_hash: *mut [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: *mut [u8; 32], // nullable
    pub quorum_merkle_root: *mut [u8; 32], // nullable
    pub masternodes: *mut *mut MasternodeEntry,
    pub masternodes_count: usize,
    pub quorum_type_maps: *mut *mut LLMQMap,
    pub quorum_type_maps_count: usize,
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQMap {
    pub llmq_type: u8,
    pub values: *mut *mut QuorumEntry,
    pub count: usize,
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeEntry {
    pub confirmed_hash: *mut [u8; 32],
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: *mut [u8; 32], // nullable
    pub is_valid: bool,
    pub key_id_voting: *mut [u8; 20],
    pub known_confirmed_at_height: u32, // nullable
    pub masternode_entry_hash: *mut [u8; 32],
    pub operator_public_key: *mut [u8; 48],
    pub previous_masternode_entry_hashes: *mut MasternodeEntryHash,
    pub previous_masternode_entry_hashes_count: usize,
    pub previous_operator_public_keys: *mut OperatorPublicKey,
    pub previous_operator_public_keys_count: usize,
    pub previous_validity: *mut Validity,
    pub previous_validity_count: usize,
    pub provider_registration_transaction_hash: *mut [u8; 32],
    pub ip_address: *mut [u8; 16],
    pub port: u16,
    pub update_height: u32,
}
impl<'a> TryRead<'a, Endian> for MasternodeEntry {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let provider_registration_transaction_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let confirmed_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let ip_address = match bytes.read_with::<UInt128>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let port = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data.swap_bytes(),
            Err(err) => { return Err(err); }
        };
        let operator_public_key = match bytes.read_with::<UInt384>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let key_id_voting = match bytes.read_with::<UInt160>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let is_valid = match bytes.read_with::<u8>(offset, LE) {
            Ok(data) => data,
            Err(_err) => 0
        };
        Ok((Self {
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: null_mut(),
            is_valid: is_valid != 0,
            key_id_voting,
            known_confirmed_at_height: 0,
            masternode_entry_hash: null_mut(),
            operator_public_key,
            previous_masternode_entry_hashes: null_mut(),
            previous_masternode_entry_hashes_count: 0,
            previous_operator_public_keys: null_mut(),
            previous_operator_public_keys_count: 0,
            previous_validity: null_mut(),
            previous_validity_count: 0,
            provider_registration_transaction_hash,
            ip_address,
            port,
            update_height: 0
        }, *offset))
    }
}


#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct QuorumEntry {
    pub all_commitment_aggregated_signature: *mut [u8; 96],
    pub commitment_hash: *mut [u8; 32], // nullable
    pub length: usize,
    pub llmq_type: LLMQType,
    pub quorum_entry_hash: *mut [u8; 32],
    pub quorum_hash: *mut [u8; 32],
    pub quorum_index: u32,
    pub quorum_public_key: *mut [u8; 48],
    pub quorum_threshold_signature: *mut [u8; 96],
    pub quorum_verification_vector_hash: *mut [u8; 32],
    pub saved: bool,
    pub signers_bitset: *mut u8,
    pub signers_bitset_length: usize,
    pub signers_count: u64,
    pub valid_members_bitset: *mut u8,
    pub valid_members_bitset_length: usize,
    pub valid_members_count: u64,
    pub verified: bool,
    pub version: u16,
}
impl<'a> TryRead<'a, Endian> for QuorumEntry {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let length = bytes.len();
        let offset = &mut 0;
        let version = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let llmq_type = match bytes.read_with::<u8>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let quorum_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let quorum_index = match version {
            2 => match bytes.read_with::<u32>(offset, LE) {
                Ok(data) => data,
                Err(err) => { return Err(err); }
            },
            _ => 0,
        };
        let signers_count = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "signers_count"}); }
        };
        *offset += signers_count.len();
        let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
        if length - *offset < signers_buffer_length {
            return Err(byte::Error::BadOffset(*offset));
        }
        let signers_bitset: &[u8] = match bytes.read_with(offset, Bytes::Len(signers_buffer_length)) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };


        let valid_members_count = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "valid_members_count"}); }
        };
        *offset += valid_members_count.len();
        let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
        if length - *offset < valid_members_count_buffer_length {
            return Err(byte::Error::BadOffset(*offset));
        }
        let valid_members_bitset: &[u8] = match bytes.read_with(offset, Bytes::Len(valid_members_count_buffer_length)) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };

        let quorum_public_key = match bytes.read_with::<UInt384>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let quorum_verification_vector_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let quorum_threshold_signature = match bytes.read_with::<UInt768>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let all_commitment_aggregated_signature = match bytes.read_with::<UInt768>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let llmq_type: LLMQType = llmq_type.into();

        Ok((Self {
            all_commitment_aggregated_signature,
            commitment_hash: null_mut(),
            length: *offset,
            llmq_type,
            quorum_entry_hash: null_mut(),
            quorum_hash,
            quorum_index,
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            saved: false,
            signers_bitset: boxed_vec(signers_bitset.to_vec()),
            signers_bitset_length: signers_bitset.len(),
            signers_count: signers_count.0,
            valid_members_bitset: boxed_vec(valid_members_bitset.to_vec()),
            valid_members_bitset_length: valid_members_bitset.len(),
            valid_members_count: valid_members_count.0,
            verified: false,
            version
        }, *offset))
    }
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct VarInt { // 9 // 72
    pub value: u64,
    pub length: usize
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct Validity { // 37 // 296
    pub block_hash: [u8; 32],
    pub block_height: u32,
    pub is_valid: bool,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct OperatorPublicKey { // 84 // 692
    pub block_hash: [u8; 32],
    pub block_height: u32,
    pub key: [u8; 48],
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeEntryHash {
    pub block_hash: [u8; 32],
    pub block_height: u32,
    pub hash: [u8; 32],
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MndiffResult {
    pub has_found_coinbase: bool, //1 byte
    pub has_valid_coinbase: bool, //1 byte
    pub has_valid_mn_list_root: bool, //1 byte
    pub has_valid_quorum_list_root: bool, //1 byte
    pub has_valid_quorums: bool, //1 byte
    pub masternode_list: *mut MasternodeList,
    pub added_masternodes: *mut *mut MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes: *mut *mut MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_quorum_type_maps: *mut *mut LLMQMap,
    pub added_quorum_type_maps_count: usize,
    pub needed_masternode_lists:  *mut *mut [u8; 32], // [u8; 32]
    pub needed_masternode_lists_count: usize,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct QuorumValidationData {
    pub items: *mut *mut [u8; 48],
    pub count: usize,
    pub commitment_hash: *mut [u8; 32],
    pub all_commitment_aggregated_signature: *mut [u8; 96],
    pub quorum_threshold_signature: *mut [u8; 96],
    pub quorum_public_key: *mut [u8; 48],
}

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessQuorumTypeCallback = unsafe extern "C" fn(quorum_type: u8, context: *const c_void) -> bool;
pub type ValidateQuorumCallback = unsafe extern "C" fn(data: *mut QuorumValidationData, context: *const c_void) -> bool;

pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(*const MasternodeList);

impl Default for MndiffResult {
    fn default() -> Self {
        MndiffResult {
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_quorum_list_root: false,
            has_valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes: null_mut(),
            modified_masternodes_count: 0,
            added_quorum_type_maps: null_mut(),
            added_quorum_type_maps_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0
        }
    }
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQTypedHash {
    pub llmq_type: u8,
    pub llmq_hash: *mut [u8; 32],
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct TransactionInput {
    pub input_hash: *mut [u8; 32],
    pub index: u32,
    pub script: *mut u8,
    pub script_length: usize,
    pub signature: *mut u8,
    pub signature_length: usize,
    pub sequence: u32,
}
impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let index = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let signature = match data_at_offset_from(bytes, offset) {
            Ok(data) => boxed(data),
            Err(_err) => null_mut()
        };
        let (signature, signature_length) = match data_at_offset_from(bytes, offset) {
            Ok(data) => (boxed_vec(data.to_vec()), data.len()),
            Err(_err) => (null_mut(), 0)
        };
        let sequence = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        Ok((Self {
            input_hash: boxed(input_hash.0),
            index,
            script: null_mut(),
            script_length: 0,
            signature,
            signature_length,
            sequence
        }, *offset))
    }
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct TransactionOutput {
    pub amount: u64,
    pub script: *mut u8,
    pub script_length: usize,
    pub address: *mut u8,
    pub address_length: usize,
}
impl<'a> TryRead<'a, Endian> for TransactionOutput {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let amount = match bytes.read_with::<u64>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let (script, script_length) = match data_at_offset_from(bytes, offset) {
            Ok(data) => (boxed_vec(data.to_vec()), data.len()),
            Err(err) => { return Err(err); }
        };
        Ok((Self {
            amount,
            script,
            script_length,
            address: null_mut(),
            address_length: 0
        }, *offset))
    }
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct Transaction {
    pub inputs: *mut *mut TransactionInput,
    pub inputs_count: usize,
    pub outputs: *mut *mut TransactionOutput,
    pub outputs_count: usize,
    pub lock_time: u32,
    pub version: u16,
    pub tx_hash: *mut [u8; 32],
    pub tx_type: TransactionType,
    pub payload_offset: usize,
    pub block_height: u32,
}
impl<'a> TryRead<'a, Endian> for Transaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let tx_type = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let tx_type = TransactionType::from(tx_type);

        let inputs_count_var = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "inputs_count_var"}); }
        };
        let inputs_count = inputs_count_var.0 as usize;
        *offset += inputs_count_var.len();
        if inputs_count == 0 && tx_type.requires_inputs() {
            return Err(byte::Error::BadOffset(*offset));
        }
        let mut inputs_vec: Vec<*mut TransactionInput> = Vec::with_capacity(inputs_count);
        for _i in 0..inputs_count {
            let input = match bytes.read_with::<TransactionInput>(offset, LE) {
                Ok(data) => data,
                Err(err) => { return Err(err); }
            };
            inputs_vec.push(boxed(input));
        }
        let inputs = boxed_vec(inputs_vec);

        let outputs_count_var = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "outputs_count_var"}); }
        };
        let outputs_count = outputs_count_var.0 as usize;
        *offset += outputs_count_var.len();
        let mut outputs_vec: Vec<*mut TransactionOutput> = Vec::new();
        for _i in 0..outputs_count {
            let output = match bytes.read_with::<TransactionOutput>(offset, LE) {
                Ok(data) => data,
                Err(err) => { return Err(err); }
            };
            outputs_vec.push(boxed(output));
        }
        let outputs = boxed_vec(outputs_vec);
        let lock_time = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        Ok((Self {
            inputs,
            inputs_count,
            outputs,
            outputs_count,
            tx_hash: null_mut(),
            version,
            tx_type,
            lock_time,
            payload_offset: *offset,
            block_height: TX_UNCONFIRMED as u32,
        }, *offset))
    }
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct CoinbaseTransaction {
    pub base: *mut Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: *mut [u8; 32],
    pub merkle_root_llmq_list: *mut [u8; 32],
}
impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let base = match bytes.read_with::<Transaction>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let extra_payload_size_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "extra_payload_size_var_int"}); }
        };
        *offset += extra_payload_size_var_int.len();
        let coinbase_transaction_version = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let height = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let merkle_root_mn_list = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let merkle_root_llmq_list =
            if coinbase_transaction_version == 2 {
                match bytes.read_with::<UInt256>(offset, LE) {
                    Ok(data) => boxed(data.0),
                    Err(err) => { return Err(err); }
                }
            } else { null_mut() };
        Ok((Self {
            base,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list
        }, *offset))
    }
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MNListDiff {
    pub base_block_hash: *mut [u8; 32],
    pub block_hash: *mut [u8; 32],
    pub total_transactions: u32,

    pub merkle_hashes: *mut u8,
    pub merkle_hashes_count: usize,

    pub merkle_flags: *mut u8,
    pub merkle_flags_count: usize,

    pub coinbase_transaction: *mut CoinbaseTransaction,

    pub deleted_masternode_hashes_count: usize,
    pub deleted_masternode_hashes: *mut *mut [u8; 32],

    pub added_or_modified_masternodes_count: usize,
    pub added_or_modified_masternodes: *mut *mut MasternodeEntry,

    pub deleted_quorums_count: usize,
    pub deleted_quorums: *mut *mut LLMQTypedHash,

    pub added_quorums_count: usize,
    pub added_quorums: *mut *mut QuorumEntry,

    pub length: usize,
    pub block_height: u32,
}

impl<'a> TryRead<'a, Endian> for MNListDiff {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let message_length = bytes.len();
        let offset = &mut 0;
        let base_block_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let block_hash = match bytes.read_with::<UInt256>(offset, LE) {
            Ok(data) => boxed(data.0),
            Err(err) => { return Err(err); }
        };
        let total_transactions = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let merkle_hash_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "merkle_hash_var_int"}); }
        };
        *offset += merkle_hash_var_int.len();
        let merkle_hashes_count = (merkle_hash_var_int.0 as usize) * 32;
        let merkle_hashes = &bytes[*offset..*offset + merkle_hashes_count];
        *offset += merkle_hashes_count;
        let merkle_flag_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "merkle_flag_var_int"}); }
        };
        *offset += merkle_flag_var_int.len();
        let merkle_flags_count = merkle_flag_var_int.0 as usize;
        let merkle_flags = &bytes[*offset..*offset + merkle_flags_count];
        *offset += merkle_flags_count;
        let coinbase_transaction = match bytes.read_with::<CoinbaseTransaction>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        if message_length - *offset < 1 {
            return Err(byte::Error::BadOffset(*offset));
        }
        let deleted_masternode_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "deleted_masternode_var_int"}); }
        };
        *offset += deleted_masternode_var_int.len();
        let deleted_masternode_hashes_count = deleted_masternode_var_int.0.clone() as usize;
        let mut deleted_masternode_hashes_vec: Vec<*mut [u8; 32]> = Vec::with_capacity(deleted_masternode_hashes_count as usize);
        for _i in 0..deleted_masternode_hashes_count {
            deleted_masternode_hashes_vec.push(match bytes.read_with::<UInt256>(offset, LE) {
                Ok(data) => boxed(data.0),
                Err(err) => { return Err(err); }
            });
        }
        let deleted_masternode_hashes = boxed_vec(deleted_masternode_hashes_vec);
        let added_masternode_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "added_masternode_var_int"}); }
        };
        *offset += added_masternode_var_int.len();
        let added_or_modified_masternodes_count = added_masternode_var_int.0.clone() as usize;
        let mut added_or_modified_masternodes_vec: Vec<*mut MasternodeEntry> = Vec::with_capacity(added_or_modified_masternodes_count);
        for _i in 0..added_or_modified_masternodes_count {
            added_or_modified_masternodes_vec.push(match bytes.read_with::<MasternodeEntry>(offset, LE) {
                Ok(data) => boxed(data),
                Err(err) => { return Err(err); }
            });
        }
        let added_or_modified_masternodes = boxed_vec(added_or_modified_masternodes_vec);
        let mut deleted_quorums: *mut *mut LLMQTypedHash = null_mut();
        let mut added_quorums: *mut *mut QuorumEntry = null_mut();
        let mut added_quorums_count = 0;
        let mut deleted_quorums_count = 0;
        if coinbase_transaction.coinbase_transaction_version >= 2 {
            // deleted quorums
            if message_length - *offset < 1 {
                return Err(byte::Error::BadOffset(*offset));
            }
            let deleted_quorums_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
                Ok(data) => data,
                Err(err) => { return Err(byte::Error::BadInput { err: "deleted_quorums_var_int"}); }
            };
            *offset += deleted_quorums_var_int.len();
            deleted_quorums_count = deleted_quorums_var_int.0.clone() as usize;
            let mut deleted_quorum_hashes_vec: Vec<*mut LLMQTypedHash> = Vec::with_capacity(deleted_quorums_count);
            for _i in 0..deleted_quorums_count {
                let llmq_type = match bytes.read_with::<LLMQType>(offset, LE) {
                    Ok(data) => data.into(),
                    Err(err) => { return Err(err); }
                };
                let llmq_hash = match bytes.read_with::<UInt256>(offset, LE) {
                    Ok(data) => boxed(data.0),
                    Err(err) => { return Err(err); }
                };
                deleted_quorum_hashes_vec.push(boxed(LLMQTypedHash { llmq_type, llmq_hash }));
            }
            deleted_quorums = boxed_vec(deleted_quorum_hashes_vec);
            // added quorums
            if message_length - *offset < 1 {
                return Err(byte::Error::BadOffset(*offset));
            }
            let added_quorums_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
                Ok(data) => data,
                Err(err) => { return Err(byte::Error::BadInput { err: "added_quorums_var_int"}); }
            };
            *offset += added_quorums_var_int.len();
            added_quorums_count = added_quorums_var_int.0.clone() as usize;
            let mut added_quorums_vec: Vec<*mut QuorumEntry> = Vec::with_capacity(added_quorums_count);
            for _i in 0..added_quorums_count {
                let quorum_entry = match bytes.read_with::<QuorumEntry>(offset, LE) {
                    Ok(data) => boxed(data),
                    Err(err) => { return Err(err); }
                };
                added_quorums_vec.push(quorum_entry);
            }
            added_quorums = boxed_vec(added_quorums_vec);
        }
        let length = *offset;
        Ok((Self {
            base_block_hash,
            block_hash,
            total_transactions,
            merkle_hashes: boxed_vec(merkle_hashes.to_vec()),
            merkle_hashes_count,
            merkle_flags: boxed_vec(merkle_flags.to_vec()),
            merkle_flags_count,
            coinbase_transaction: boxed(coinbase_transaction),
            deleted_masternode_hashes_count,
            deleted_masternode_hashes,
            added_or_modified_masternodes_count,
            added_or_modified_masternodes,
            deleted_quorums_count,
            deleted_quorums,
            added_quorums_count,
            added_quorums,
            length,
            block_height: 0
        }, *offset))
    }
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct QuorumRotationInfo {
    pub snapshot_at_h_c: *mut QuorumSnapshot,
    pub snapshot_at_h_2c: *mut QuorumSnapshot,
    pub snapshot_at_h_3c: *mut QuorumSnapshot,
    pub list_diff_tip: *mut MNListDiff,
    pub list_diff_at_h: *mut MNListDiff,
    pub list_diff_at_h_c: *mut MNListDiff,
    pub list_diff_at_h_2c: *mut MNListDiff,
    pub list_diff_at_h_3c: *mut MNListDiff,
    pub extra_share: bool,
    pub snapshot_at_h_4c: *mut QuorumSnapshot, // exist only if extra_share is true
    pub list_diff_at_h_4c: *mut MNListDiff, // exist only if extra_share is true
    pub block_hash_list_num: u32,
    pub block_hash_list: *mut *mut [u8; 32],
    pub snapshot_list_num: u32,
    pub snapshot_list: *mut *mut QuorumSnapshot,
    pub mn_list_diff_list_num: u32,
    pub mn_list_diff_list: *mut *mut MNListDiff,
}

impl Default for QuorumRotationInfo {
    fn default() -> Self {
        QuorumRotationInfo {
            snapshot_at_h_c: null_mut(),
            snapshot_at_h_2c: null_mut(),
            snapshot_at_h_3c: null_mut(),
            list_diff_tip: null_mut(),
            list_diff_at_h: null_mut(),
            list_diff_at_h_c: null_mut(),
            list_diff_at_h_2c: null_mut(),
            list_diff_at_h_3c: null_mut(),
            extra_share: false,
            snapshot_at_h_4c: null_mut(),
            list_diff_at_h_4c: null_mut(),
            block_hash_list_num: 0,
            block_hash_list: null_mut(),
            snapshot_list_num: 0,
            snapshot_list: null_mut(),
            mn_list_diff_list_num: 0,
            mn_list_diff_list: null_mut()
        }
    }
}

impl<'a> TryRead<'a, Endian> for QuorumRotationInfo {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let message_length = bytes.len();
        let offset = &mut 0;
        let snapshot_at_h_c = match bytes.read_with::<QuorumSnapshot>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let snapshot_at_h_2c = match bytes.read_with::<QuorumSnapshot>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let snapshot_at_h_3c = match bytes.read_with::<QuorumSnapshot>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let list_diff_tip = match bytes.read_with::<MNListDiff>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let list_diff_at_h = match bytes.read_with::<MNListDiff>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let list_diff_at_h_c = match bytes.read_with::<MNListDiff>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let list_diff_at_h_2c = match bytes.read_with::<MNListDiff>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let list_diff_at_h_3c = match bytes.read_with::<MNListDiff>(offset, LE) {
            Ok(data) => boxed(data),
            Err(err) => { return Err(err); }
        };
        let extra_share = match bool::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "extra_share"}); }
        };
        *offset += 1;

        let (snapshot_at_h_4c, list_diff_at_h_4c) = if extra_share {
            (match bytes.read_with::<QuorumSnapshot>(offset, LE) {
                Ok(data) => boxed(data),
                Err(err) => { return Err(err); }
            }, match bytes.read_with::<MNListDiff>(offset, LE) {
                Ok(data) => boxed(data),
                Err(err) => { return Err(err); }
            })
        } else {
            (null_mut(), null_mut())
        };
        let block_hash_list_num = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let mut block_hash_list_vec: Vec<*mut [u8; 32]> = Vec::with_capacity(block_hash_list_num as usize);
        for _i in 0..block_hash_list_num {
            let block_hash = match bytes.read_with::<UInt256>(offset, LE) {
                Ok(data) => boxed(data.0),
                Err(err) => { return Err(err); }
            };
            block_hash_list_vec.push(block_hash);
        }
        let block_hash_list = boxed_vec(block_hash_list_vec);

        let snapshot_list_num = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let mut snapshot_list_vec: Vec<*mut QuorumSnapshot> = Vec::with_capacity(snapshot_list_num as usize);
        for _i in 0..snapshot_list_num {
            let snapshot = match bytes.read_with::<QuorumSnapshot>(offset, LE) {
                Ok(data) => boxed(data),
                Err(err) => { return Err(err); }
            };
            snapshot_list_vec.push(snapshot);
        }
        let snapshot_list = boxed_vec(snapshot_list_vec);

        let mn_list_diff_list_num = match bytes.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let mut mn_list_diff_list_vec: Vec<*mut MNListDiff> = Vec::with_capacity(mn_list_diff_list_num as usize);
        for _i in 0..mn_list_diff_list_num {
            let mnlist_diff = match bytes.read_with::<MNListDiff>(offset, LE) {
                Ok(data) => boxed(data),
                Err(err) => { return Err(err); }
            };
            mn_list_diff_list_vec.push(mnlist_diff);
        }
        let mn_list_diff_list = boxed_vec(mn_list_diff_list_vec);

        Ok((Self {
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            list_diff_tip,
            list_diff_at_h,
            list_diff_at_h_c,
            list_diff_at_h_2c,
            list_diff_at_h_3c,
            extra_share,
            snapshot_at_h_4c,
            list_diff_at_h_4c,
            block_hash_list_num,
            block_hash_list,
            snapshot_list_num,
            snapshot_list,
            mn_list_diff_list_num,
            mn_list_diff_list
        }, *offset))

    }
}

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct QuorumSnapshot {
    pub member_list_length: usize,
    pub member_list: *mut u8,
    // Skiplist at height n
    pub skip_list_length: usize,
    pub skip_list: *mut u32,
    //  Mode of the skip list
    pub skip_list_mode: QuorumSnapshotSkipMode,
}
impl<'a> TryRead<'a, Endian> for QuorumSnapshot {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let member_list_size_var_int = match crate::consensus::encode::VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput { err: "member_list_size_var_int" }); }
        };
        *offset += member_list_size_var_int.len();
        let member_list_size = member_list_size_var_int.0 as usize;
        let member_list_num = (member_list_size + 7) / 8;
        let member_list: &[u8] = bytes.read_with(offset, Bytes::Len(member_list_num)).unwrap();
        let skip_list_mode = match bytes.read_with::<QuorumSnapshotSkipMode>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let skip_list_size = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let skip_list_length = skip_list_size as usize;
        let mut skip_list: Vec<u32> = Vec::with_capacity(skip_list_length);
        for i in 0..skip_list_size {
            skip_list.push(match bytes.read_with::<u32>(offset, LE) {
                Ok(data) => data,
                Err(err) => { return Err(err); }
            });
        }
        Ok((Self {
            member_list_length: member_list_size,
            member_list: boxed_vec(member_list.to_vec()),
            skip_list_length,
            skip_list: boxed_vec(skip_list),
            skip_list_mode
        }, *offset))

    }
}
