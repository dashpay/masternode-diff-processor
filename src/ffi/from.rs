use std::collections::{BTreeMap, HashMap};
use std::slice;
use crate::common::block_data::BlockData;
use crate::common::llmq_type::LLMQType;
use crate::common::socket_address::SocketAddress;
use crate::consensus::encode;
use crate::crypto::byte_util::{Reversable, UInt128, UInt160, UInt256, UInt384, UInt768};
use crate::ffi::to::ToFFI;
use crate::ffi::wrapped_types;
use crate::masternode::{masternode_entry, masternode_list, quorum_entry};
use crate::masternode::quorum_entry::QUORUM_DEFAULT_VERSION;
use crate::processing::{mn_list_diff, quorum_rotation_info, quorum_snapshot};
use crate::transactions::{coinbase_transaction, transaction};

pub trait FromFFI<'a> {
    type Item: ToFFI<'a>;
    unsafe fn decode(&self) -> Self::Item;
}
impl<'a> FromFFI<'a> for wrapped_types::TransactionInput {
    type Item = transaction::TransactionInput<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let input_hash = UInt256(*self.input_hash);
        let script_length = self.script_length;
        let script = if self.script.is_null() || script_length == 0 {
            None
        } else {
            Some(slice::from_raw_parts(self.script, script_length))
        };
        let signature_length = self.signature_length;
        let signature = if self.signature.is_null() || signature_length == 0 {
            None
        } else {
            Some(slice::from_raw_parts(self.signature, signature_length))
        };
        Self::Item {
            input_hash,
            index: self.index,
            script,
            signature,
            sequence: self.sequence
        }
    }
}

impl<'a> FromFFI<'a> for wrapped_types::TransactionOutput {
    type Item = transaction::TransactionOutput<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let script_length = self.script_length;
        let script = if self.script.is_null() || script_length == 0 {
            None
        } else {
            Some(slice::from_raw_parts(self.script, script_length))
        };
        let address_length = self.address_length;
        let address = if self.address.is_null() || address_length == 0 {
            None
        } else {
            Some(slice::from_raw_parts(self.address, address_length))
        };

        Self::Item {
            amount: self.amount,
            script,
            address
        }
    }
}
impl<'a> FromFFI<'a> for wrapped_types::Transaction {
    type Item = transaction::Transaction<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let inputs = (0..self.inputs_count)
            .into_iter()
            .map(|i| (*(*(self.inputs.offset(i as isize)))).decode())
            .collect();
        let outputs = (0..self.outputs_count)
            .into_iter()
            .map(|i| (*(*(self.outputs.offset(i as isize)))).decode())
            .collect();
        Self::Item {
            inputs,
            outputs,
            lock_time: self.lock_time,
            version: self.version,
            tx_hash: None,
            tx_type: self.tx_type,
            payload_offset: self.payload_offset,
            block_height: self.block_height
        }
    }
}
impl<'a> FromFFI<'a> for wrapped_types::CoinbaseTransaction {
    type Item = coinbase_transaction::CoinbaseTransaction<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let merkle_root_llmq_list = if self.merkle_root_llmq_list.is_null() {
            None
        } else {
            Some(UInt256(*self.merkle_root_llmq_list))
        };
        Self::Item {
            base: (*self.base).decode(),
            coinbase_transaction_version: self.coinbase_transaction_version,
            height: self.height,
            merkle_root_mn_list: UInt256(*self.merkle_root_mn_list),
            merkle_root_llmq_list
        }
    }
}

impl<'a> FromFFI<'a> for wrapped_types::MasternodeList {
    type Item = masternode_list::MasternodeList<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let block_hash = UInt256(*self.block_hash);
        let known_height = self.known_height;
        let masternode_merkle_root = if self.masternode_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*self.masternode_merkle_root))
        };
        let quorum_merkle_root = if self.quorum_merkle_root.is_null() {
            None
        } else {
            Some(UInt256(*self.quorum_merkle_root))
        };
        let masternodes: BTreeMap<UInt256, masternode_entry::MasternodeEntry> =
            (0..self.masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, i| {
                    let raw_value = *(*(self.masternodes.offset(i as isize)));
                    let value = raw_value.decode();
                    let key = value.provider_registration_transaction_hash.clone().reversed();
                    acc.insert(key, value);
                    acc
                });
        let quorums: HashMap<LLMQType, HashMap<UInt256, quorum_entry::QuorumEntry>> =
            (0..self.quorum_type_maps_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let llmq_map = *(*(self.quorum_type_maps.offset(i as isize)));
                    let key = LLMQType::from(llmq_map.llmq_type);
                    let value: HashMap<UInt256, quorum_entry::QuorumEntry> =
                        (0..llmq_map.count)
                            .into_iter()
                            .fold(HashMap::new(), |mut acc, j| {
                                let raw_value = *(*(llmq_map.values.offset(j as isize)));
                                let value = raw_value.decode();
                                let key = value.quorum_hash.clone();
                                acc.insert(key, value);
                                acc
                            });
                    acc.insert(key, value);
                    acc
                });
        let unwrapped = Self::Item {
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

impl<'a> FromFFI<'a> for wrapped_types::MasternodeEntry {
    type Item = masternode_entry::MasternodeEntry;
    unsafe fn decode(&self) -> Self::Item {
        let provider_registration_transaction_hash = UInt256(*self.provider_registration_transaction_hash);
        let confirmed_hash = UInt256(*self.confirmed_hash);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if self.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
            None
        } else {
            Some(UInt256(*self.confirmed_hash_hashed_with_provider_registration_transaction_hash))
        };
        let ip_address = UInt128(*self.ip_address);
        let port = self.port;
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = UInt384(*self.operator_public_key);
        let previous_operator_public_keys: BTreeMap<BlockData, UInt384> =
            (0..self.previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_operator_public_keys.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = UInt384(obj.key);
                    acc.insert(key, value);
                    acc
                });
        let previous_masternode_entry_hashes: BTreeMap<BlockData, UInt256> =
            (0..self.previous_masternode_entry_hashes_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_masternode_entry_hashes.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = UInt256(obj.hash);
                    acc.insert(key, value);
                    acc
                });
        let previous_validity: BTreeMap<BlockData, bool> =
            (0..self.previous_validity_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_validity.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = obj.is_valid;
                    acc.insert(key, value);
                    acc
                });
        let update_height = self.update_height;
        let key_id_voting = UInt160(*self.key_id_voting);
        let known_confirmed_at_height = if self.known_confirmed_at_height > 0 {
            Some(self.known_confirmed_at_height)
        } else {
            None
        };
        let is_valid = self.is_valid;
        let masternode_entry_hash = UInt256(*self.masternode_entry_hash);
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
}

impl<'a> FromFFI<'a> for wrapped_types::QuorumEntry {
    type Item = quorum_entry::QuorumEntry<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let version = self.version;
        let quorum_hash = UInt256(*self.quorum_hash);
        let quorum_index = if self.version == QUORUM_DEFAULT_VERSION { None } else { Some(self.quorum_index) };
        let quorum_public_key = UInt384(*self.quorum_public_key);
        let quorum_threshold_signature = UInt768(*self.quorum_threshold_signature);
        let quorum_verification_vector_hash = UInt256(*self.quorum_verification_vector_hash);
        let all_commitment_aggregated_signature = UInt768(*self.all_commitment_aggregated_signature);
        let llmq_type = self.llmq_type;
        let signers_count = encode::VarInt(self.signers_count);
        let signers_bitset = slice::from_raw_parts(self.signers_bitset, self.signers_bitset_length);
        let valid_members_count = encode::VarInt(self.valid_members_count);
        let valid_members_bitset = slice::from_raw_parts(self.valid_members_bitset, self.valid_members_bitset_length);
        let length = self.length;
        let quorum_entry_hash = UInt256(*self.quorum_entry_hash);
        let verified = self.verified;
        let saved = self.saved;
        let commitment_hash = if self.commitment_hash.is_null() {
            None
        } else {
            Some(UInt256(*self.commitment_hash))
        };
        quorum_entry::QuorumEntry {
            version,
            quorum_hash,
            quorum_index,
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
}

impl<'a> FromFFI<'a> for wrapped_types::MNListDiff {
    type Item = mn_list_diff::MNListDiff<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let merkle_hashes_count = self.merkle_hashes_count;
        let merkle_hashes = slice::from_raw_parts(self.merkle_hashes, merkle_hashes_count);
        let merkle_flags_count = self.merkle_flags_count;
        let merkle_flags = slice::from_raw_parts(self.merkle_flags, merkle_flags_count);

        let deleted_masternode_hashes = (0..self.deleted_masternode_hashes_count)
            .into_iter()
            .map(|i| {
                let hash = *self.deleted_masternode_hashes.offset(i as isize);
                UInt256(*hash)
            })
            .collect();


        let added_or_modified_masternodes: BTreeMap<UInt256, masternode_entry::MasternodeEntry> =
            (0..self.added_or_modified_masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, i| {
                    let raw_value = *(*(self.added_or_modified_masternodes.offset(i as isize)));
                    let value = raw_value.decode();
                    let key = value.provider_registration_transaction_hash.clone().reversed();
                    acc.insert(key, value);
                    acc
                });

        let deleted_quorums: HashMap<LLMQType, Vec<UInt256>> =
            (0..self.deleted_quorums_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let obj = *(*(self.deleted_quorums.offset(i as isize)));
                    let key = LLMQType::from(obj.llmq_type);
                    let llmq_hash = UInt256(*obj.llmq_hash);
                    if acc.contains_key(&key) {
                        acc.get_mut(&key).unwrap().push(llmq_hash);
                    } else {
                        acc.insert(key, vec![llmq_hash]);
                    }
                    acc
                });
        let added_quorums: HashMap<LLMQType, HashMap<UInt256, quorum_entry::QuorumEntry>> =
            (0..self.added_quorums_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let quorum_entry = *(*(self.added_quorums.offset(i as isize)));
                    let entry = quorum_entry.decode();
                    acc
                        .entry(entry.llmq_type)
                        .or_insert(HashMap::new())
                        .insert(entry.quorum_hash, entry);
                    acc
                });
        mn_list_diff::MNListDiff {
            base_block_hash: UInt256(*self.base_block_hash),
            block_hash: UInt256(*self.block_hash),
            total_transactions: self.total_transactions,
            merkle_hashes,
            merkle_hashes_count,
            merkle_flags,
            merkle_flags_count,
            coinbase_transaction: (*self.coinbase_transaction).decode(),
            deleted_masternode_hashes,
            added_or_modified_masternodes,
            deleted_quorums,
            added_quorums,
            length: self.length,
            block_height: self.block_height
        }
    }
}
impl<'a> FromFFI<'a> for wrapped_types::QuorumSnapshot {
    type Item = quorum_snapshot::QuorumSnapshot<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let member_list = slice::from_raw_parts(self.member_list, self.member_list_length);
        let skip_list = (0..self.skip_list_length)
            .into_iter()
            .map(|i| *(self.skip_list.offset(i as isize)))
            .collect();
        let skip_list_mode = self.skip_list_mode;
        Self::Item {
            member_list,
            skip_list,
            skip_list_mode
        }
    }
}

impl<'a> FromFFI<'a> for wrapped_types::QuorumRotationInfo {
    type Item = quorum_rotation_info::QuorumRotationInfo<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let snapshot_at_h_c = (*self.snapshot_at_h_c).decode();
        let snapshot_at_h_2c = (*self.snapshot_at_h_2c).decode();
        let snapshot_at_h_3c = (*self.snapshot_at_h_3c).decode();
        let list_diff_tip = (*self.list_diff_tip).decode();
        let list_diff_at_h = (*self.list_diff_at_h).decode();
        let list_diff_at_h_c = (*self.list_diff_at_h_c).decode();
        let list_diff_at_h_2c = (*self.list_diff_at_h_2c).decode();
        let list_diff_at_h_3c = (*self.list_diff_at_h_3c).decode();
        let extra_share = self.extra_share;
        let (snapshot_at_h_4c, list_diff_at_h_4c) = if extra_share {
            (Some((*self.snapshot_at_h_4c).decode()), Some((*self.list_diff_at_h_4c).decode()))
        } else {
            (None, None)
        };
        let block_hash_list = (0..self.block_hash_list_num)
            .into_iter()
            .map(|i| UInt256(*(*(self.block_hash_list.offset(i as isize)))))
            .collect();
        let snapshot_list = (0..self.snapshot_list_num)
            .into_iter()
            .map(|i| (*(*(self.snapshot_list.offset(i as isize)))).decode())
            .collect();
        let mn_list_diff_list = (0..self.mn_list_diff_list_num)
            .into_iter()
            .map(|i| (*(*(self.mn_list_diff_list.offset(i as isize)))).decode())
            .collect();
        Self::Item {
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
            block_hash_list,
            snapshot_list,
            mn_list_diff_list,
        }
    }
}
