use std::ffi::c_void;
use std::ptr::null_mut;
use crate::common::llmq_type::LLMQType;
use crate::wrapped_types::wrapper::boxed;

/// This types reflected for FFI
#[repr(C)] #[derive(Clone, Debug)]
pub struct MasternodeListExt {
    pub list: *mut MasternodeList,
    pub exists: bool,
}
impl Default for MasternodeListExt {
    fn default() -> Self {
        Self { list: null_mut(), exists: false }
    }
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct MasternodeList {
    pub block_hash: *mut [u8; 32],
    pub known_height: u32,
    pub masternode_merkle_root: *mut [u8; 32],
    // pub masternode_merkle_root: *const u8, // 32
    pub masternode_merkle_root_exists: bool,
    // pub quorum_merkle_root: *const u8, // 32
    pub quorum_merkle_root: *mut [u8; 32], // 32
    pub quorum_merkle_root_exists: bool,
    pub masternodes_keys: *mut *mut [u8; 32], //32
    pub masternodes_values: *mut *mut MasternodeEntry,
    pub masternodes_count: usize,
    pub quorums_keys: *mut *mut u8, //1 (LLMQType)
    pub quorums_values: *mut *mut LLMQMap,
    pub quorums_count: usize,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct LLMQMap {
    pub keys: *mut *mut [u8; 32], //32
    pub values: *mut *mut QuorumEntry,
    pub count: usize,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct MasternodeEntry {
    // pub confirmed_hash: *const u8, // 32
    pub confirmed_hash: *mut [u8; 32], // 32
    // pub confirmed_hash_hashed_with_provider_registration_transaction_hash: *const u8, // 32
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: *mut [u8; 32], // 32
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash_exists: bool,
    pub is_valid: bool,
    // pub key_id_voting: *const u8, //20
    pub key_id_voting: *mut [u8; 20], //20
    pub known_confirmed_at_height: u32,
    pub known_confirmed_at_height_exists: bool,
    // pub masternode_entry_hash: *const u8, //32
    pub masternode_entry_hash: *mut [u8; 32], //32
    // pub operator_public_key: *const u8, //48
    pub operator_public_key: *mut [u8; 48], //48
    pub previous_operator_public_keys: *mut *mut OperatorPublicKey,
    pub previous_operator_public_keys_count: usize,
    pub previous_masternode_entry_hashes: *mut *mut MasternodeEntryHash,
    pub previous_masternode_entry_hashes_count: usize,
    pub previous_validity: *mut *mut Validity,
    pub previous_validity_count: usize,
    // pub provider_registration_transaction_hash: *const u8, // 32
    pub provider_registration_transaction_hash: *mut [u8; 32], // 32
    pub ip_address: *mut [u8; 16],
    pub port: u16,
    pub update_height: u32,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct QuorumEntry {
    pub all_commitment_aggregated_signature: *mut [u8; 96], // 96,
    pub commitment_hash: *mut [u8; 32], // 32
    pub commitment_hash_exists: bool,
    pub length: usize,
    pub llmq_type: LLMQType,
    pub quorum_entry_hash: *mut [u8; 32], // 32
    pub quorum_hash: *mut [u8; 32], // 32,
    pub quorum_public_key: *mut [u8; 48], // 48,
    pub quorum_threshold_signature: *mut [u8; 96], // 96,
    pub quorum_verification_vector_hash: *mut [u8; 32], // 32,
    pub saved: bool,
    pub signers_bitset: *const u8, // ?
    pub signers_bitset_length: usize, // ?
    pub signers_count: u64,
    pub valid_members_bitset: *const u8, // ?
    pub valid_members_bitset_length: usize, // ?
    pub valid_members_count: u64,
    pub verified: bool,
    pub version: u16,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct VarInt {
    pub value: u64,
    pub length: usize
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct Validity {
    pub block_hash: *mut [u8; 32], // 32
    pub block_height: u32,
    pub is_valid: bool,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct OperatorPublicKey {
    pub block_hash: *mut [u8; 32], // 32
    pub block_height: u32,
    pub key: *mut [u8; 48], // 48
}
#[repr(C)] #[derive(Clone, Debug)]
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
    pub masternode_list: *mut MasternodeListExt,
    pub added_masternodes_keys: *mut *mut [u8; 32], // [u8; 32]
    pub added_masternodes_values: *mut *mut MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes_keys: *mut *mut [u8; 32], // [u8; 32]
    pub modified_masternodes_values: *mut *mut MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_quorums_keys: *mut *mut u8,
    pub added_quorums_values: *mut *mut LLMQMap,
    pub added_quorums_count: usize,
    pub needed_masternode_lists:  *mut *mut [u8; 32], // [u8; 32]
    pub needed_masternode_lists_count: usize,
}
#[repr(C)] #[derive(Clone, Debug)]
pub struct QuorumValidationData {
    pub items: *mut *mut [u8; 48],
    pub count: usize,
    pub commitment_hash: *mut [u8; 32],
    pub all_commitment_aggregated_signature: *mut [u8; 96],
    pub quorum_threshold_signature: *mut [u8; 96],
    pub quorum_public_key: *mut [u8; 48],
}

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *mut c_void);
pub type ShouldProcessQuorumTypeCallback = unsafe extern "C" fn(quorum_type: u8, context: *mut c_void) -> bool;
pub type ValidateQuorumCallback = unsafe extern "C" fn(data: *mut QuorumValidationData, context: *mut c_void) -> bool;

pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *mut c_void) -> u32;
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *mut c_void) -> *mut MasternodeListExt;

impl Default for MndiffResult {
    fn default() -> Self {
        MndiffResult {
            found_coinbase: false,
            valid_coinbase: false,
            root_mn_list_valid: false,
            root_quorum_list_valid: false,
            valid_quorums: false,
            masternode_list: boxed(MasternodeListExt { list: null_mut(), exists: false }),
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
    use crate::wrapped_types::{LLMQMap, MasternodeEntry, MasternodeEntryHash, MasternodeList, MasternodeListExt, OperatorPublicKey, QuorumEntry, Validity};

    pub fn boxed<T>(obj: T) -> *mut T { Box::into_raw(Box::new(obj)) }

    pub fn wrap_masternode_list(list: masternode_list::MasternodeList) -> wrapped_types::MasternodeList {
        let block_hash = boxed(list.block_hash.0);
        let known_height = list.known_height;
        let (quorum_merkle_root, quorum_merkle_root_exists) = if list.quorum_merkle_root.is_none() {
            (null_mut(), false)
        } else {
            (boxed(list.quorum_merkle_root.unwrap().0), true)
        };
        let (masternode_merkle_root, masternode_merkle_root_exists) = if list.masternode_merkle_root.is_none() {
            (null_mut(), false)
        } else {
            (boxed(list.masternode_merkle_root.unwrap().0), true)
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
            masternode_merkle_root_exists,
            quorum_merkle_root,
            quorum_merkle_root_exists,
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
        let (confirmed_hash_hashed_with_provider_registration_transaction_hash, confirmed_hash_hashed_with_provider_registration_transaction_hash_exists) = if entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_none() {
            (null_mut(), false)
        } else {
            (boxed(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.unwrap().0), true)
        };
        let is_valid = entry.is_valid;
        let key_id_voting = boxed(entry.key_id_voting.0);
        let (known_confirmed_at_height, known_confirmed_at_height_exists) = if entry.known_confirmed_at_height.is_none() {
            (0, false)
        } else {
            (entry.known_confirmed_at_height.unwrap(), true)
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
            confirmed_hash_hashed_with_provider_registration_transaction_hash_exists,
            is_valid,
            key_id_voting,
            known_confirmed_at_height,
            known_confirmed_at_height_exists,
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
        let (commitment_hash, commitment_hash_exists) = if entry.commitment_hash.is_none() {
            (null_mut(), false)
        } else {
            (boxed(entry.commitment_hash.unwrap().0), true)
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
            commitment_hash_exists,
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
    pub fn wrap_quorums_map(quorums: HashMap<LLMQType, HashMap<UInt256, crate::masternode::quorum_entry::QuorumEntry>>) -> (*mut *mut u8, *mut *mut LLMQMap, usize) {
        let quorums_count = quorums.len();
        let mut quorums_keys_vec: Vec<*mut u8> = Vec::with_capacity(quorums_count);
        let mut quorums_values_vec: Vec<*mut LLMQMap> = Vec::with_capacity(quorums_count);
        quorums.into_iter().for_each(|(llmq_type, map)| {
            quorums_keys_vec.push(boxed(llmq_type.into()));
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


    pub unsafe fn unwrap_quorum_entry(entry: *mut wrapped_types::QuorumEntry) -> quorum_entry::QuorumEntry<'static> {
        let q_entry = Box::from_raw(entry);
        let version = q_entry.version;
        let quorum_hash = UInt256(*Box::from_raw(q_entry.quorum_hash));
        let quorum_public_key = UInt384(*Box::from_raw(q_entry.quorum_public_key));
        let quorum_threshold_signature = UInt768(*Box::from_raw(q_entry.quorum_threshold_signature));
        let quorum_verification_vector_hash = UInt256(*Box::from_raw(q_entry.quorum_verification_vector_hash));
        let all_commitment_aggregated_signature = UInt768(*Box::from_raw(q_entry.all_commitment_aggregated_signature));
        let llmq_type = q_entry.llmq_type;
        let signers_count = encode::VarInt(q_entry.signers_count);
        let valid_members_count = encode::VarInt(q_entry.valid_members_count);
        let signers_bitset = slice::from_raw_parts(q_entry.signers_bitset, q_entry.signers_bitset_length);
        let valid_members_bitset = slice::from_raw_parts(q_entry.valid_members_bitset, q_entry.valid_members_bitset_length);
        let length = q_entry.length;
        let quorum_entry_hash = UInt256(*Box::from_raw(q_entry.quorum_entry_hash));
        let verified = q_entry.verified;
        let saved = q_entry.saved;
        let commitment_hash = if q_entry.commitment_hash_exists {
            Some(UInt256(*Box::from_raw(q_entry.commitment_hash)))
        } else {
            None
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

    pub unsafe fn unwrap_masternode_entry(entry: *mut wrapped_types::MasternodeEntry) -> masternode_entry::MasternodeEntry {
        let mn_entry = Box::from_raw(entry);
        let provider_registration_transaction_hash = UInt256(*Box::from_raw(mn_entry.provider_registration_transaction_hash));
        let confirmed_hash = UInt256(*Box::from_raw(mn_entry.confirmed_hash));
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if mn_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash_exists {
            Some(UInt256(*Box::from_raw(mn_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash)))
        } else {
            None
        };
        let ip_address = UInt128(*Box::from_raw(mn_entry.ip_address));
        let port = mn_entry.port;
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = UInt384(*Box::from_raw(mn_entry.operator_public_key));
        let previous_operator_public_keys: BTreeMap<BlockData, UInt384> = if mn_entry.previous_operator_public_keys_count == 0 {
            BTreeMap::new()
        } else {
            Vec::from_raw_parts(
                mn_entry.previous_operator_public_keys,
                mn_entry.previous_operator_public_keys_count,
                mn_entry.previous_operator_public_keys_count)
                .into_iter()
                .map(|opk| Box::from_raw(opk))
                .fold(BTreeMap::new(),|mut acc, entry| {
                    let value_box = Box::from_raw(entry.key);
                    let key_box = Box::from_raw(entry.block_hash);
                    let key = BlockData { height: entry.block_height, hash: UInt256(*key_box) };
                    let value = UInt384(*value_box);
                    acc.insert(key, value);
                    acc
                })
        };
        let previous_masternode_entry_hashes: HashMap<BlockData, UInt256>= if mn_entry.previous_masternode_entry_hashes_count == 0 {
            HashMap::new()
        } else {
            Vec::from_raw_parts(
                mn_entry.previous_masternode_entry_hashes,
                mn_entry.previous_masternode_entry_hashes_count,
                mn_entry.previous_masternode_entry_hashes_count)
                .into_iter()
                .map(|meh| Box::from_raw(meh))
                .fold(HashMap::new(),|mut acc, entry| {
                    let value_box = Box::from_raw(entry.hash);
                    let key_box = Box::from_raw(entry.block_hash);
                    let key = BlockData { height: entry.block_height, hash: UInt256(*key_box) };
                    let value = UInt256(*value_box);
                    acc.insert(key, value);
                    acc
                })
        };
        let previous_validity: HashMap<BlockData, bool> = if mn_entry.previous_validity_count == 0 {
            HashMap::new()
        } else {
            Vec::from_raw_parts(
                mn_entry.previous_validity,
                mn_entry.previous_validity_count,
                mn_entry.previous_validity_count)
                .into_iter()
                .map(|meh| Box::from_raw(meh))
                .fold(HashMap::new(),|mut acc, entry| {
                    let value = entry.is_valid;
                    let key_box = Box::from_raw(entry.block_hash);
                    let key = BlockData { height: entry.block_height, hash: UInt256(*key_box) };
                    acc.insert(key, value);
                    acc
                })
        };
        let update_height = mn_entry.update_height;
        let key_id_voting = UInt160(*Box::from_raw(mn_entry.key_id_voting));
        let known_confirmed_at_height = if mn_entry.known_confirmed_at_height_exists {
            Some(mn_entry.known_confirmed_at_height)
        } else {
            None
        };
        let is_valid = mn_entry.is_valid;
        let masternode_entry_hash = UInt256(*Box::from_raw(mn_entry.masternode_entry_hash));
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

    pub unsafe fn unwrap_masternode_list_ext(list: *mut MasternodeListExt) -> Option<crate::masternode::masternode_list::MasternodeList<'static>> {
        let list_ext = Box::from_raw(list);
        if !list_ext.exists {
            None
        } else {
            let mn_list = Box::from_raw(list_ext.list);
            let block_hash = UInt256(*Box::from_raw(mn_list.block_hash));
            let known_height = mn_list.known_height;
            let masternode_merkle_root = if mn_list.masternode_merkle_root_exists {
                Some(UInt256(*Box::from_raw(mn_list.masternode_merkle_root)))
            } else {
                None
            };
            let quorum_merkle_root = if mn_list.quorum_merkle_root_exists {
                Some(UInt256(*Box::from_raw(mn_list.quorum_merkle_root)))
            } else {
                None
            };

            let masternodes_count = mn_list.masternodes_count;
            let masternodes_keys = Vec::from_raw_parts(mn_list.masternodes_keys, masternodes_count, masternodes_count);
            let masternodes_values = Vec::from_raw_parts(mn_list.masternodes_values, masternodes_count, masternodes_count);

            let masternodes: BTreeMap<UInt256, masternode_entry::MasternodeEntry> =
                (0..masternodes_count)
                    .into_iter()
                    .fold(BTreeMap::new(),|mut acc, i| {
                        let key = UInt256(*Box::from_raw(masternodes_keys[i]));
                        let value = unwrap_masternode_entry(masternodes_values[i]);
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
                        let qk = Box::from_raw(quorums_keys[i]);
                        let llmq_map = Box::from_raw(quorums_values[i]);
                        let count = llmq_map.count;

                        let keys = Vec::from_raw_parts(llmq_map.keys, count, count);
                        let values = Vec::from_raw_parts(llmq_map.values, count, count);

                        let key = LLMQType::from(*qk);
                        let value: HashMap<UInt256, quorum_entry::QuorumEntry> =
                            (0..count)
                                .into_iter()
                                .fold(HashMap::new(), |mut acc, j| {
                                    let hash = Box::from_raw(keys[j]);
                                    let value = unwrap_quorum_entry(values[j]);
                                    acc.insert(UInt256(*hash), value);
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
            Some(unwrapped)
        }
    }
}