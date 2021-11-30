use std::ffi::c_void;
use std::ptr::null_mut;
use crate::common::llmq_type::LLMQType;

/// This types reflected for FFI
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeList {
    pub block_hash: *mut [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: *mut [u8; 32], // nullable
    pub quorum_merkle_root: *mut [u8; 32], // nullable
    pub masternodes_keys: *mut *mut [u8; 32],
    pub masternodes_values: *mut *mut MasternodeEntry,
    pub masternodes_count: usize,
    pub quorums_keys: *mut u8, //1 (LLMQType)
    pub quorums_values: *mut *mut LLMQMap,
    pub quorums_count: usize,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQMap {
    pub keys: *mut *mut [u8; 32], //32
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
    pub previous_masternode_entry_hashes: *mut *mut MasternodeEntryHash,
    pub previous_masternode_entry_hashes_count: usize,
    pub previous_operator_public_keys: *mut *mut OperatorPublicKey,
    pub previous_operator_public_keys_count: usize,
    pub previous_validity: *mut *mut Validity,
    pub previous_validity_count: usize,
    pub provider_registration_transaction_hash: *mut [u8; 32],
    pub ip_address: *mut [u8; 16],
    pub port: u16,
    pub update_height: u32,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct QuorumEntry {
    pub all_commitment_aggregated_signature: *mut [u8; 96],
    pub commitment_hash: *mut [u8; 32], // nullable
    pub length: usize,
    pub llmq_type: LLMQType,
    pub quorum_entry_hash: *mut [u8; 32],
    pub quorum_hash: *mut [u8; 32],
    pub quorum_public_key: *mut [u8; 48],
    pub quorum_threshold_signature: *mut [u8; 96],
    pub quorum_verification_vector_hash: *mut [u8; 32],
    pub saved: bool,
    pub signers_bitset: *const u8,
    pub signers_bitset_length: usize,
    pub signers_count: u64,
    pub valid_members_bitset: *const u8,
    pub valid_members_bitset_length: usize,
    pub valid_members_count: u64,
    pub verified: bool,
    pub version: u16,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct VarInt {
    pub value: u64,
    pub length: usize
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct Validity {
    pub block_hash: *mut [u8; 32],
    pub block_height: u32,
    pub is_valid: bool,
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct OperatorPublicKey {
    pub block_hash: *mut [u8; 32], // 32
    pub block_height: u32,
    pub key: *mut [u8; 48], // 48
}
#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MasternodeEntryHash {
    pub block_hash: *mut [u8; 32], // 32
    pub block_height: u32,
    pub hash: *mut [u8; 32], // 32
}

#[repr(C)] #[derive(Debug)]
pub struct MndiffResult {
    pub found_coinbase: bool, //1 byte
    pub valid_coinbase: bool, //1 byte
    pub root_mn_list_valid: bool, //1 byte
    pub root_quorum_list_valid: bool, //1 byte
    pub valid_quorums: bool, //1 byte
    pub masternode_list: *mut MasternodeList,
    pub added_masternodes_keys: *mut *mut [u8; 32], // [u8; 32]
    pub added_masternodes_values: *mut *mut MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes_keys: *mut *mut [u8; 32], // [u8; 32]
    pub modified_masternodes_values: *mut *mut MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_quorums_keys: *mut u8,
    pub added_quorums_values: *mut *mut LLMQMap,
    pub added_quorums_count: usize,
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
            found_coinbase: false,
            valid_coinbase: false,
            root_mn_list_valid: false,
            root_quorum_list_valid: false,
            valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes_keys: null_mut(),
            added_masternodes_values: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes_keys: null_mut(),
            modified_masternodes_values: null_mut(),
            modified_masternodes_count: 0,
            added_quorums_keys: null_mut(),
            added_quorums_values: null_mut(),
            added_quorums_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0
        }
    }
}

pub mod wrapper {
    use std::collections::{BTreeMap, HashMap};
    use std::{mem, slice};
    use std::ptr::null_mut;
    use crate::common::block_data::BlockData;
    use crate::common::llmq_type::LLMQType;
    use crate::common::socket_address::SocketAddress;
    use crate::consensus::encode;
    use crate::crypto::byte_util::{UInt128, UInt160, UInt256, UInt384, UInt768};
    use crate::{masternode::{masternode_list, masternode_entry, quorum_entry}, wrapped_types};
    use crate::wrapped_types::{LLMQMap, MasternodeEntry, MasternodeEntryHash, MasternodeList, OperatorPublicKey, QuorumEntry, Validity};

    pub fn boxed<T>(obj: T) -> *mut T { Box::into_raw(Box::new(obj)) }

    pub fn wrap_masternode_list(list: masternode_list::MasternodeList) -> wrapped_types::MasternodeList {
        let block_hash = boxed(list.block_hash.0);
        let known_height = list.known_height;
        let quorum_merkle_root = if list.quorum_merkle_root.is_none() {
            null_mut()
        } else {
            boxed(list.quorum_merkle_root.unwrap().0)
        };
        let masternode_merkle_root = if list.masternode_merkle_root.is_none() {
            null_mut()
        } else {
            boxed(list.masternode_merkle_root.unwrap().0)
        };
        let (masternodes_keys,
            masternodes_values,
            masternodes_count) = wrap_masternodes_map(list.masternodes);
        let (quorums_keys,
            quorums_values,
            quorums_count) = wrap_quorums_map(list.quorums);
        let wrapped = MasternodeList {
            block_hash,
            known_height,
            masternode_merkle_root,
            quorum_merkle_root,
            masternodes_keys,
            masternodes_values,
            masternodes_count,
            quorums_keys,
            quorums_values,
            quorums_count
        };
        wrapped
    }

    pub fn wrap_llmq_map(map: HashMap<UInt256, quorum_entry::QuorumEntry>) -> LLMQMap {
        let count = map.len();
        let mut quorums_for_type_keys_vec: Vec<*mut [u8; 32]> = Vec::with_capacity(count);
        let mut quorums_for_type_values_vec: Vec<*mut QuorumEntry> = Vec::with_capacity(count);
        map.into_iter().for_each(|(hash, entry)| {
            quorums_for_type_keys_vec.push(boxed(hash.0));
            quorums_for_type_values_vec.push(boxed(wrap_quorum_entry(entry)));
        });
        let mut quorums_for_type_keys_slice = quorums_for_type_keys_vec.into_boxed_slice();
        let mut quorums_for_type_values_slice = quorums_for_type_values_vec.into_boxed_slice();
        let keys = quorums_for_type_keys_slice.as_mut_ptr();
        let values = quorums_for_type_values_slice.as_mut_ptr();
        mem::forget(quorums_for_type_keys_slice);
        mem::forget(quorums_for_type_values_slice);
        LLMQMap { keys, values, count }
    }
    pub fn wrap_masternode_entry(entry: crate::masternode::masternode_entry::MasternodeEntry) -> MasternodeEntry {
        let confirmed_hash = boxed(entry.confirmed_hash.0);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_none() {
            null_mut()
        } else {
            boxed(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.unwrap().0)
        };
        let is_valid = entry.is_valid;
        let key_id_voting = boxed(entry.key_id_voting.0);
        let known_confirmed_at_height = if entry.known_confirmed_at_height.is_none() {
            0
        } else {
            entry.known_confirmed_at_height.unwrap()
        };
        let masternode_entry_hash = boxed(entry.masternode_entry_hash.0);
        let operator_public_key = boxed(entry.operator_public_key.0);

        let previous_operator_public_keys_count = entry.previous_operator_public_keys.len();
        let mut operator_public_keys_vec: Vec<*mut OperatorPublicKey> = Vec::with_capacity(previous_operator_public_keys_count);
        entry.previous_operator_public_keys
            .into_iter()
            .for_each(|(block, key)| {
                operator_public_keys_vec.push(boxed(OperatorPublicKey {
                    block_hash: boxed(block.hash.0),
                    block_height: block.height,
                    key: boxed(key.0)
                }))
            });
        let mut operator_public_keys_slice = operator_public_keys_vec.into_boxed_slice();
        let previous_operator_public_keys = operator_public_keys_slice.as_mut_ptr();
        mem::forget(operator_public_keys_slice);

        let previous_masternode_entry_hashes_count = entry.previous_masternode_entry_hashes.len();
        let mut masternode_entry_hashes_vec: Vec<*mut MasternodeEntryHash> = Vec::with_capacity(previous_masternode_entry_hashes_count);
        entry.previous_masternode_entry_hashes
            .into_iter()
            .for_each(|(block, hash)| {
                masternode_entry_hashes_vec.push(boxed(MasternodeEntryHash {
                    block_hash: boxed(block.hash.0),
                    block_height: block.height,
                    hash: boxed(hash.0)
                }))
            });
        let mut masternode_entry_hashes_slice = masternode_entry_hashes_vec.into_boxed_slice();
        let previous_masternode_entry_hashes = masternode_entry_hashes_slice.as_mut_ptr();
        mem::forget(masternode_entry_hashes_slice);

        let previous_validity_count = entry.previous_validity.len();
        let mut validity_vec: Vec<*mut Validity> = Vec::with_capacity(previous_validity_count);
        entry.previous_validity
            .into_iter()
            .for_each(|(block, is_valid)| {
                validity_vec.push(boxed(Validity {
                    block_hash: boxed(block.hash.0),
                    block_height: block.height,
                    is_valid
                }))
            });
        let mut validity_slice = validity_vec.into_boxed_slice();
        let previous_validity = validity_slice.as_mut_ptr();
        mem::forget(validity_slice);

        let provider_registration_transaction_hash = boxed(entry.provider_registration_transaction_hash.0);
        let SocketAddress { ip_address: ip, port } = entry.socket_address;
        let ip_address = boxed(ip.0);
        let update_height= entry.update_height;
        MasternodeEntry {
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash,
            is_valid,
            key_id_voting,
            known_confirmed_at_height,
            masternode_entry_hash,
            operator_public_key,
            previous_operator_public_keys,
            previous_operator_public_keys_count,
            previous_masternode_entry_hashes,
            previous_masternode_entry_hashes_count,
            previous_validity,
            previous_validity_count,
            provider_registration_transaction_hash,
            ip_address,
            port,
            update_height
        }
    }

    pub fn wrap_quorum_entry(entry: crate::masternode::quorum_entry::QuorumEntry) -> QuorumEntry {
        let all_commitment_aggregated_signature = boxed(entry.all_commitment_aggregated_signature.0);
        let commitment_hash = if entry.commitment_hash.is_none() {
            null_mut()
        } else {
            boxed(entry.commitment_hash.unwrap().0)
        };
        let quorum_entry_hash = boxed(entry.quorum_entry_hash.0);
        let quorum_hash = boxed(entry.quorum_hash.0);
        let quorum_public_key = boxed(entry.quorum_public_key.0);
        let quorum_threshold_signature = boxed(entry.quorum_threshold_signature.0);
        let quorum_verification_vector_hash = boxed(entry.quorum_verification_vector_hash.0);
        let signers_bitset = entry.signers_bitset.as_ptr();
        let signers_bitset_length = entry.signers_bitset.len();
        let signers_count = entry.signers_count.0;
        let valid_members_bitset = entry.valid_members_bitset.as_ptr();
        let valid_members_bitset_length = entry.valid_members_bitset.len();
        let valid_members_count = entry.valid_members_count.0;
        QuorumEntry {
            all_commitment_aggregated_signature,
            commitment_hash,
            length: entry.length,
            llmq_type: entry.llmq_type,
            quorum_entry_hash,
            quorum_hash,
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            saved: entry.saved,
            signers_bitset,
            signers_bitset_length,
            signers_count,
            valid_members_bitset,
            valid_members_count,
            verified: entry.verified,
            version: entry.version,
            valid_members_bitset_length
        }
    }

    pub fn wrap_masternodes_map(map: BTreeMap<UInt256, crate::masternode::masternode_entry::MasternodeEntry>) -> (*mut *mut [u8; 32], *mut *mut MasternodeEntry, usize) {
        let count = map.len();
        let mut keys_vec: Vec<*mut [u8; 32]> = Vec::with_capacity(count);
        let mut values_vec: Vec<*mut MasternodeEntry> = Vec::with_capacity(count);
        map.into_iter().for_each(|(hash, entry)| {
            keys_vec.push(boxed(hash.0));
            values_vec.push(boxed(wrap_masternode_entry(entry)));
        });
        let mut keys_slice = keys_vec.into_boxed_slice();
        let mut values_slice = values_vec.into_boxed_slice();
        let keys = keys_slice.as_mut_ptr();
        let values = values_slice.as_mut_ptr();
        mem::forget(keys_slice);
        mem::forget(values_slice);
        (keys, values, count)
    }
    pub fn wrap_quorums_map(quorums: HashMap<LLMQType, HashMap<UInt256, crate::masternode::quorum_entry::QuorumEntry>>) -> (*mut u8, *mut *mut LLMQMap, usize) {
        let quorums_count = quorums.len();
        let mut quorums_keys_vec: Vec<u8> = Vec::with_capacity(quorums_count);
        let mut quorums_values_vec: Vec<*mut LLMQMap> = Vec::with_capacity(quorums_count);
        quorums.into_iter().for_each(|(llmq_type, map)| {
            let llmq = llmq_type.into();
            quorums_keys_vec.push(llmq);
            quorums_values_vec.push(boxed(wrap_llmq_map(map)));
        });
        let mut quorums_keys_slice = quorums_keys_vec.into_boxed_slice();
        let mut quorums_values_slice = quorums_values_vec.into_boxed_slice();
        let quorums_keys = quorums_keys_slice.as_mut_ptr();
        let quorums_values = quorums_values_slice.as_mut_ptr();
        mem::forget(quorums_keys_slice);
        mem::forget(quorums_values_slice);
        (quorums_keys, quorums_values, quorums_count)
    }


    pub unsafe fn unwrap_quorum_entry<'a>(entry: wrapped_types::QuorumEntry) -> quorum_entry::QuorumEntry<'a> {
        let version = entry.version;
        let quorum_hash = UInt256(*entry.quorum_hash);
        let quorum_public_key = UInt384(*entry.quorum_public_key);
        let quorum_threshold_signature = UInt768(*entry.quorum_threshold_signature);
        let quorum_verification_vector_hash = UInt256(*entry.quorum_verification_vector_hash);
        let all_commitment_aggregated_signature = UInt768(*entry.all_commitment_aggregated_signature);
        let llmq_type = entry.llmq_type;
        let signers_count = encode::VarInt(entry.signers_count);
        let valid_members_count = encode::VarInt(entry.valid_members_count);
        let signers_bitset = slice::from_raw_parts(entry.signers_bitset, entry.signers_bitset_length);
        let valid_members_bitset = slice::from_raw_parts(entry.valid_members_bitset, entry.valid_members_bitset_length);
        let length = entry.length;
        let quorum_entry_hash = UInt256(*entry.quorum_entry_hash);
        let verified = entry.verified;
        let saved = entry.saved;
        let commitment_hash = if entry.commitment_hash.is_null() {
            None
        } else {
            Some(UInt256(*entry.commitment_hash))
        };
        quorum_entry::QuorumEntry {
            version,
            quorum_hash,
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            all_commitment_aggregated_signature,
            signers_count,
            llmq_type,
            valid_members_count,
            signers_bitset,
            valid_members_bitset,
            length,
            quorum_entry_hash,
            verified,
            saved,
            commitment_hash
        }
    }

    pub unsafe fn unwrap_masternode_entry(entry: wrapped_types::MasternodeEntry) -> masternode_entry::MasternodeEntry {
        let provider_registration_transaction_hash = UInt256(*entry.provider_registration_transaction_hash);
        let confirmed_hash = UInt256(*entry.confirmed_hash);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
            None
        } else {
            Some(UInt256(*entry.confirmed_hash_hashed_with_provider_registration_transaction_hash))
        };
        let ip_address = UInt128(*entry.ip_address);
        let port = entry.port;
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = UInt384(*entry.operator_public_key);
        let previous_operator_public_keys_count = entry.previous_operator_public_keys_count;
        let previous_operator_public_keys: BTreeMap<BlockData, UInt384> = if previous_operator_public_keys_count == 0 {
            BTreeMap::new()
        } else {
            (0..previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let OperatorPublicKey { block_hash, block_height: height, key} = **entry.previous_operator_public_keys.offset(i as isize);
                    let block = BlockData { height, hash: UInt256(*block_hash) };
                    let public_key = UInt384(*key);
                    acc.insert(block, public_key);
                    acc
                })
        };
        let previous_masternode_entry_hashes_count = entry.previous_masternode_entry_hashes_count;
        let previous_masternode_entry_hashes: BTreeMap<BlockData, UInt256>= if previous_masternode_entry_hashes_count == 0 {
            BTreeMap::new()
        } else {
            (0..previous_masternode_entry_hashes_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let MasternodeEntryHash { block_hash, block_height: height, hash} = **entry.previous_masternode_entry_hashes.offset(i as isize);
                    let key = BlockData { height, hash: UInt256(*block_hash) };
                    let value = UInt256(*hash);
                    acc.insert(key, value);
                    acc
                })
        };
        let previous_validity_count = entry.previous_validity_count;
        let previous_validity: BTreeMap<BlockData, bool> = if entry.previous_validity_count == 0 {
            BTreeMap::new()
        } else {
            (0..previous_validity_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let Validity { block_hash, block_height: height, is_valid: value } = **entry.previous_validity.offset(i as isize);
                    let key = BlockData { height, hash: UInt256(*block_hash) };
                    acc.insert(key, value);
                    acc
                })
        };
        let update_height = entry.update_height;
        let key_id_voting = UInt160(*entry.key_id_voting);
        let known_confirmed_at_height = if entry.known_confirmed_at_height > 0 {
            Some(entry.known_confirmed_at_height)
        } else {
            None
        };
        let is_valid = entry.is_valid;
        let masternode_entry_hash = UInt256(*entry.masternode_entry_hash);
        masternode_entry::MasternodeEntry {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash,
            socket_address,
            operator_public_key,
            previous_operator_public_keys,
            previous_masternode_entry_hashes,
            previous_validity,
            known_confirmed_at_height,
            update_height,
            key_id_voting,
            is_valid,
            masternode_entry_hash
        }
    }

    pub unsafe fn unwrap_boxed_masternode_entry(entry: wrapped_types::MasternodeEntry) -> masternode_entry::MasternodeEntry {
        let provider_registration_transaction_hash = UInt256(*entry.provider_registration_transaction_hash);
        let confirmed_hash = UInt256(*entry.confirmed_hash);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
            None
        } else {
            Some(UInt256(*entry.confirmed_hash_hashed_with_provider_registration_transaction_hash))
        };
        let ip_address = UInt128(*entry.ip_address);
        let port = entry.port;
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = UInt384(*entry.operator_public_key);
        let previous_operator_public_keys: BTreeMap<BlockData, UInt384> = if entry.previous_operator_public_keys_count == 0 {
            BTreeMap::new()
        } else {
            Vec::from_raw_parts(
                entry.previous_operator_public_keys,
                entry.previous_operator_public_keys_count,
                entry.previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, entry| {
                    let key = BlockData { height: (*entry).block_height, hash: UInt256(*(*entry).block_hash) };
                    let value = UInt384(*(*entry).key);
                    acc.insert(key, value);
                    acc
                })
        };
        let previous_masternode_entry_hashes: BTreeMap<BlockData, UInt256>= if entry.previous_masternode_entry_hashes_count == 0 {
            BTreeMap::new()
        } else {
            Vec::from_raw_parts(
                entry.previous_masternode_entry_hashes,
                entry.previous_masternode_entry_hashes_count,
                entry.previous_masternode_entry_hashes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, entry| {
                    let value_box = (*entry).hash;
                    let key_box = (*entry).block_hash;
                    let key = BlockData { height: (*entry).block_height, hash: UInt256(*key_box) };
                    let value = UInt256(*value_box);
                    acc.insert(key, value);
                    acc
                })
        };
        let previous_validity: BTreeMap<BlockData, bool> = if entry.previous_validity_count == 0 {
            BTreeMap::new()
        } else {
            Vec::from_raw_parts(
                entry.previous_validity,
                entry.previous_validity_count,
                entry.previous_validity_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, entry| {
                    let value = (*entry).is_valid;
                    let key_box = (*entry).block_hash;
                    let key = BlockData { height: (*entry).block_height, hash: UInt256(*key_box) };
                    acc.insert(key, value);
                    acc
                })
        };
        let update_height = entry.update_height;
        let key_id_voting = UInt160(*entry.key_id_voting);
        let known_confirmed_at_height = if entry.known_confirmed_at_height > 0 {
            Some(entry.known_confirmed_at_height)
        } else {
            None
        };
        let is_valid = entry.is_valid;
        let masternode_entry_hash = UInt256(*entry.masternode_entry_hash);
        masternode_entry::MasternodeEntry {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash,
            socket_address,
            operator_public_key,
            previous_operator_public_keys,
            previous_masternode_entry_hashes,
            previous_validity,
            known_confirmed_at_height,
            update_height,
            key_id_voting,
            is_valid,
            masternode_entry_hash
        }
    }

    pub unsafe fn unwrap_boxed_masternode_list<'a>(mn_list: MasternodeList) -> crate::masternode::masternode_list::MasternodeList<'a> {
        let block_hash = UInt256(*mn_list.block_hash);
        let known_height = mn_list.known_height;
        let masternode_merkle_root = if mn_list.masternode_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*mn_list.masternode_merkle_root))
        };
        let quorum_merkle_root = if mn_list.quorum_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*mn_list.quorum_merkle_root))
        };
        let masternodes_count = mn_list.masternodes_count;
        let masternodes_keys = Vec::from_raw_parts(mn_list.masternodes_keys, masternodes_count, masternodes_count);
        let masternodes_values = Vec::from_raw_parts(mn_list.masternodes_values, masternodes_count, masternodes_count);
        let masternodes: BTreeMap<UInt256, masternode_entry::MasternodeEntry> =
            (0..masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, i| {
                    let raw_key = masternodes_keys[i];
                    let key = UInt256(*raw_key);
                    let raw_value = masternodes_values[i];
                    let value = unwrap_boxed_masternode_entry(*raw_value);
                    acc.insert(key, value);
                    acc
                });
        let quorums_count = mn_list.quorums_count;
        let quorums_keys = Vec::from_raw_parts(mn_list.quorums_keys, quorums_count, quorums_count);
        let quorums_values = Vec::from_raw_parts(mn_list.quorums_values, quorums_count, quorums_count);
        let quorums: HashMap<LLMQType, HashMap<UInt256, quorum_entry::QuorumEntry>> =
            (0..quorums_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let qk = quorums_keys[i];
                    let llmq_map = *quorums_values[i];
                    let count = llmq_map.count;
                    let keys = Vec::from_raw_parts(llmq_map.keys, count, count);
                    let values = Vec::from_raw_parts(llmq_map.values, count, count);
                    let key = LLMQType::from(qk);
                    let value: HashMap<UInt256, quorum_entry::QuorumEntry> =
                        (0..count)
                            .into_iter()
                            .fold(HashMap::new(), |mut acc, j| {
                                let key = UInt256(*keys[j]);
                                let value = unwrap_quorum_entry(*values[j]);
                                acc.insert(key, value);
                                acc
                            });
                    acc.insert(key, value);
                    acc
                });
        let unwrapped = masternode_list::MasternodeList {
            block_hash,
            known_height,
            masternode_merkle_root,
            quorum_merkle_root,
            masternodes,
            quorums
        };
        unwrapped
    }

    pub unsafe fn unwrap_masternode_list<'a>(mn_list: *const MasternodeList) -> crate::masternode::masternode_list::MasternodeList<'a> {
        let block_hash = UInt256(*(*mn_list).block_hash);
        let known_height = (*mn_list).known_height;
        let masternode_merkle_root = if (*mn_list).masternode_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*(*mn_list).masternode_merkle_root))
        };
        let quorum_merkle_root = if (*mn_list).quorum_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*(*mn_list).quorum_merkle_root))
        };
        let masternodes_count = (*mn_list).masternodes_count;
        let masternodes: BTreeMap<UInt256, masternode_entry::MasternodeEntry> =
            (0..masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, i| {
                    let raw_key = *(*((*mn_list).masternodes_keys.offset(i as isize)));
                    let key = UInt256(raw_key);
                    let raw_value = *(*((*mn_list).masternodes_values.offset(i as isize)));
                    let value = unwrap_masternode_entry(raw_value);
                    acc.insert(key, value);
                    acc
                });
        let quorums_count = (*mn_list).quorums_count;
        let quorums_keys = (*mn_list).quorums_keys;
        let quorums_values = (*mn_list).quorums_values;
        let quorums: HashMap<LLMQType, HashMap<UInt256, quorum_entry::QuorumEntry>> =
            (0..quorums_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let raw_key = *((*mn_list).quorums_keys.offset(i as isize));
                    let key = LLMQType::from(raw_key);
                    let llmq_map = *(*((*mn_list).quorums_values.offset(i as isize)));
                    let count = llmq_map.count;
                    let value: HashMap<UInt256, quorum_entry::QuorumEntry> =
                        (0..count)
                            .into_iter()
                            .fold(HashMap::new(), |mut acc, j| {
                                let raw_key = *(*(llmq_map.keys.offset(j as isize)));
                                let key = UInt256(raw_key);
                                let raw_value = *(*(llmq_map.values.offset(j as isize)));
                                let value = unwrap_quorum_entry(raw_value);
                                acc.insert(key, value);
                                acc
                            });
                    acc.insert(key, value);
                    acc
                });
        let unwrapped = masternode_list::MasternodeList {
            block_hash,
            known_height,
            masternode_merkle_root,
            quorum_merkle_root,
            masternodes,
            quorums
        };
        unwrapped
    }
}
pub mod unboxer {
    use crate::wrapped_types::{LLMQMap, MasternodeEntry, MasternodeList, MndiffResult, QuorumEntry, QuorumValidationData};
    pub unsafe fn unbox_any<T>(any: *mut T) {
        let _ = Box::from_raw(any);
    }
    pub unsafe fn unbox_simple_vec<T>(vec: Vec<*mut T>) {
        for &x in vec.iter() {
            unbox_any(x);
        }
    }
    pub unsafe fn unbox_masternode_entry(x: *mut MasternodeEntry) {
        let entry = Box::from_raw(x);
        unbox_any(entry.confirmed_hash);
        if !entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
            unbox_any(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash);
        }
        unbox_any(entry.key_id_voting);
        unbox_any(entry.masternode_entry_hash);
        unbox_any(entry.operator_public_key);
        let previous_masternode_entry_hashes = Vec::from_raw_parts(entry.previous_masternode_entry_hashes, entry.previous_masternode_entry_hashes_count, entry.previous_masternode_entry_hashes_count);
        for &x in previous_masternode_entry_hashes.iter() {
            let entry = Box::from_raw(x);
            unbox_any(entry.block_hash);
            unbox_any(entry.hash);
        }
        let previous_operator_public_keys = Vec::from_raw_parts(entry.previous_operator_public_keys, entry.previous_operator_public_keys_count, entry.previous_operator_public_keys_count);
        for &x in previous_operator_public_keys.iter() {
            let entry = Box::from_raw(x);
            unbox_any(entry.block_hash);
            unbox_any(entry.key);
        }
        let previous_validity = Vec::from_raw_parts(entry.previous_validity, entry.previous_validity_count, entry.previous_validity_count);
        for &x in previous_validity.iter() {
            let entry = Box::from_raw(x);
            unbox_any(entry.block_hash);
        }
        unbox_any(entry.provider_registration_transaction_hash);
        unbox_any(entry.ip_address);
    }

    pub unsafe fn unbox_quorum_entry(x: *mut QuorumEntry) {
        let entry = Box::from_raw(x);
        let _ = unbox_any(entry.all_commitment_aggregated_signature);
        let _ = unbox_any(entry.quorum_entry_hash);
        let _ = unbox_any(entry.quorum_hash);
        let _ = unbox_any(entry.quorum_public_key);
        let _ = unbox_any(entry.quorum_threshold_signature);
        let _ = unbox_any(entry.quorum_verification_vector_hash);
        if !entry.commitment_hash.is_null() {
            let _ = unbox_any(entry.commitment_hash);
        }
    }

    pub unsafe fn unbox_llmq_map(x: *mut LLMQMap) {
        let entry = Box::from_raw(x);
        let keys = Vec::from_raw_parts(entry.keys, entry.count, entry.count);
        let values = Vec::from_raw_parts(entry.values, entry.count, entry.count);
        unbox_simple_vec(keys);
        for &x in values.iter() {
            unbox_quorum_entry(x);
        }
    }
    pub unsafe fn unbox_masternode_list(masternode_list: Box<MasternodeList>) {
        let _ = Box::from_raw(masternode_list.block_hash);
        if !masternode_list.masternode_merkle_root.is_null() {
            let _ = Box::from_raw(masternode_list.masternode_merkle_root);
        }
        if !masternode_list.quorum_merkle_root.is_null() {
            unbox_any(masternode_list.quorum_merkle_root);
        }
        let masternodes_keys = Vec::from_raw_parts(masternode_list.masternodes_keys, masternode_list.masternodes_count, masternode_list.masternodes_count);
        unbox_simple_vec(masternodes_keys);
        let masternodes_values = Vec::from_raw_parts(masternode_list.masternodes_values, masternode_list.masternodes_count, masternode_list.masternodes_count);
        unbox_masternode_vec(masternodes_values);
        let quorums_keys = Vec::from_raw_parts(masternode_list.quorums_keys, masternode_list.quorums_count, masternode_list.quorums_count);
        //unbox_simple_vec(quorums_keys);
        let quorums_values = Vec::from_raw_parts(masternode_list.quorums_values, masternode_list.quorums_count, masternode_list.quorums_count);
        unbox_llmq_map_vec(quorums_values);
    }
    pub unsafe fn unbox_vec_elements<T>(vec: Vec<*mut T>) {
        for &x in vec.iter() {
            let _ = Box::from_raw(x);
        }
    }

    pub unsafe fn unbox_masternode_vec(vec: Vec<*mut MasternodeEntry>) {
        for &x in vec.iter() {
            unbox_masternode_entry(x);
        }
    }

    pub unsafe fn unbox_llmq_map_vec(vec: Vec<*mut LLMQMap>) {
        for &x in vec.iter() {
            unbox_llmq_map(x);
        }
    }

    pub unsafe fn unbox_quorum_validation_data(quorum_validation_data: *mut QuorumValidationData) {
        let result = Box::from_raw(quorum_validation_data);
        unbox_any(result.all_commitment_aggregated_signature);
        unbox_any(result.commitment_hash);
        unbox_any(result.quorum_public_key);
        unbox_any(result.quorum_threshold_signature);
        let items = Vec::from_raw_parts(result.items, result.count, result.count);
        unbox_simple_vec(items);
    }

    pub unsafe fn unbox_result(result: *mut MndiffResult) {
        let result = Box::from_raw(result);
        let masternode_list = Box::from_raw(result.masternode_list);
        unbox_masternode_list(masternode_list);
        let added_masternodes_keys = Vec::from_raw_parts(result.added_masternodes_keys, result.added_masternodes_count, result.added_masternodes_count);
        let added_masternodes_values = Vec::from_raw_parts(result.added_masternodes_values, result.added_masternodes_count, result.added_masternodes_count);
        let modified_masternodes_keys = Vec::from_raw_parts(result.modified_masternodes_keys, result.modified_masternodes_count, result.modified_masternodes_count);
        let modified_masternodes_values = Vec::from_raw_parts(result.modified_masternodes_values, result.modified_masternodes_count, result.modified_masternodes_count);
        let added_quorums_keys = Vec::from_raw_parts(result.added_quorums_keys, result.added_quorums_count, result.added_quorums_count);
        let needed_masternode_lists = Vec::from_raw_parts(result.needed_masternode_lists, result.needed_masternode_lists_count, result.needed_masternode_lists_count);
        unbox_simple_vec(added_masternodes_keys);
        unbox_masternode_vec(added_masternodes_values);
        unbox_simple_vec(modified_masternodes_keys);
        unbox_masternode_vec(modified_masternodes_values);
        //unbox_simple_vec(added_quorums_keys);
        unbox_simple_vec(needed_masternode_lists);
    }
}
