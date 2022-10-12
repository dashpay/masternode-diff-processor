use crate::ffi::to::ToFFI;
use crate::types;
use dash_spv_models::common;
use dash_spv_models::common::block::Block;
use dash_spv_models::common::llmq_type::LLMQType;
use dash_spv_models::common::socket_address::SocketAddress;
use dash_spv_models::llmq::{mn_list_diff, rotation_info, snapshot};
use dash_spv_models::masternode::llmq_entry::LLMQ_DEFAULT_VERSION;
use dash_spv_models::masternode::{llmq_entry, masternode_entry, masternode_list};
use dash_spv_models::tx::{coinbase_transaction, transaction};
use dash_spv_primitives::consensus::encode;
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::byte_util::{
    Reversable, UInt128, UInt160, UInt256, UInt384, UInt768,
};
use dash_spv_primitives::crypto::var_array::VarArray;
use std::collections::BTreeMap;
use std::slice;

pub trait FromFFI<'a> {
    type Item: ToFFI<'a>;
    unsafe fn decode(&self) -> Self::Item;
}
impl<'a> FromFFI<'a> for types::TransactionInput {
    type Item = transaction::TransactionInput;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            input_hash: UInt256(*self.input_hash),
            index: self.index,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(Vec::from_raw_parts(
                    self.script,
                    self.script_length,
                    self.script_length,
                ))
                //Some(slice::from_raw_parts(self.script, self.script_length))
            },
            signature: if self.signature.is_null() || self.signature_length == 0 {
                None
            } else {
                Some(Vec::from_raw_parts(
                    self.signature,
                    self.signature_length,
                    self.signature_length,
                ))
                // Some(slice::from_raw_parts(self.signature, self.signature_length))
            },
            sequence: self.sequence,
        }
    }
}

impl<'a> FromFFI<'a> for types::TransactionOutput {
    type Item = transaction::TransactionOutput;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            amount: self.amount,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(Vec::from_raw_parts(
                    self.script,
                    self.script_length,
                    self.script_length,
                ))
                //Some(slice::from_raw_parts(self.script, self.script_length))
            },
            address: if self.address.is_null() || self.address_length == 0 {
                None
            } else {
                Some(Vec::from_raw_parts(
                    self.address,
                    self.address_length,
                    self.address_length,
                ))
                //Some(slice::from_raw_parts(self.address, self.address_length))
            },
        }
    }
}
impl<'a> FromFFI<'a> for types::Transaction {
    type Item = transaction::Transaction;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            inputs: (0..self.inputs_count)
                .into_iter()
                .map(|i| (*(*(self.inputs.offset(i as isize)))).decode())
                .collect(),
            outputs: (0..self.outputs_count)
                .into_iter()
                .map(|i| (*(*(self.outputs.offset(i as isize)))).decode())
                .collect(),
            lock_time: self.lock_time,
            version: self.version,
            tx_hash: if self.tx_hash.is_null() {
                None
            } else {
                Some(UInt256(*self.tx_hash))
            },
            tx_type: self.tx_type,
            payload_offset: self.payload_offset,
            block_height: self.block_height,
        }
    }
}
impl<'a> FromFFI<'a> for types::CoinbaseTransaction {
    type Item = coinbase_transaction::CoinbaseTransaction;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            base: (*self.base).decode(),
            coinbase_transaction_version: self.coinbase_transaction_version,
            height: self.height,
            merkle_root_mn_list: UInt256(*self.merkle_root_mn_list),
            merkle_root_llmq_list: if self.merkle_root_llmq_list.is_null() {
                None
            } else {
                Some(UInt256(*self.merkle_root_llmq_list))
            },
        }
    }
}

impl<'a> FromFFI<'a> for types::MasternodeList {
    type Item = masternode_list::MasternodeList;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            block_hash: UInt256(*self.block_hash),
            known_height: self.known_height,
            masternode_merkle_root: if self.masternode_merkle_root.is_null() {
                None
            } else {
                Some(UInt256(*self.masternode_merkle_root))
            },
            llmq_merkle_root: if self.llmq_merkle_root.is_null() {
                None
            } else {
                Some(UInt256(*self.llmq_merkle_root))
            },
            masternodes: (0..self.masternodes_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let value = (*(*(self.masternodes.offset(i as isize)))).decode();
                    let key = value
                        .provider_registration_transaction_hash
                        .clone()
                        .reversed();
                    acc.insert(key, value);
                    acc
                },
            ),
            quorums: (0..self.llmq_type_maps_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let llmq_map = *(*(self.llmq_type_maps.offset(i as isize)));
                    let key = LLMQType::from(llmq_map.llmq_type);
                    let value: BTreeMap<UInt256, llmq_entry::LLMQEntry> = (0..llmq_map.count)
                        .into_iter()
                        .fold(BTreeMap::new(), |mut acc, j| {
                            let raw_value = *(*(llmq_map.values.offset(j as isize)));
                            let value = raw_value.decode();
                            let key = value.llmq_hash.clone();
                            acc.insert(key, value);
                            acc
                        });
                    acc.insert(key, value);
                    acc
                },
            ),
        }
    }
}

impl<'a> FromFFI<'a> for types::MasternodeEntry {
    type Item = masternode_entry::MasternodeEntry;
    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            provider_registration_transaction_hash: UInt256(
                *self.provider_registration_transaction_hash,
            ),
            confirmed_hash: UInt256(*self.confirmed_hash),
            confirmed_hash_hashed_with_provider_registration_transaction_hash: if self
                .confirmed_hash_hashed_with_provider_registration_transaction_hash
                .is_null()
            {
                None
            } else {
                Some(UInt256(
                    *self.confirmed_hash_hashed_with_provider_registration_transaction_hash,
                ))
            },
            socket_address: SocketAddress {
                ip_address: UInt128(*self.ip_address),
                port: self.port,
            },
            operator_public_key: UInt384(*self.operator_public_key),
            previous_operator_public_keys: (0..self.previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_operator_public_keys.offset(i as isize);
                    let key = Block {
                        height: obj.block_height,
                        hash: UInt256(obj.block_hash),
                    };
                    let value = UInt384(obj.key);
                    acc.insert(key, value);
                    acc
                }),
            previous_entry_hashes: (0..self.previous_entry_hashes_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let obj = *self.previous_entry_hashes.offset(i as isize);
                    let key = Block {
                        height: obj.block_height,
                        hash: UInt256(obj.block_hash),
                    };
                    let value = UInt256(obj.hash);
                    acc.insert(key, value);
                    acc
                },
            ),
            previous_validity: (0..self.previous_validity_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let obj = *self.previous_validity.offset(i as isize);
                    let key = Block {
                        height: obj.block_height,
                        hash: UInt256(obj.block_hash),
                    };
                    let value = obj.is_valid;
                    acc.insert(key, value);
                    acc
                },
            ),
            known_confirmed_at_height: if self.known_confirmed_at_height > 0 {
                Some(self.known_confirmed_at_height)
            } else {
                None
            },
            update_height: self.update_height,
            key_id_voting: UInt160(*self.key_id_voting),
            is_valid: self.is_valid,
            entry_hash: UInt256(*self.entry_hash),
        }
    }
}

impl<'a> FromFFI<'a> for types::LLMQEntry {
    type Item = llmq_entry::LLMQEntry;

    unsafe fn decode(&self) -> Self::Item {
        let signers_bitset =
            slice::from_raw_parts(self.signers_bitset as *const u8, self.signers_bitset_length)
                .to_vec();
        let valid_members_bitset = slice::from_raw_parts(
            self.valid_members_bitset as *const u8,
            self.valid_members_bitset_length,
        )
        .to_vec();
        Self::Item {
            version: self.version,
            llmq_hash: UInt256(*self.llmq_hash),
            index: if self.version == LLMQ_DEFAULT_VERSION {
                None
            } else {
                Some(self.index)
            },
            public_key: UInt384(*self.public_key),
            threshold_signature: UInt768(*self.threshold_signature),
            verification_vector_hash: UInt256(*self.verification_vector_hash),
            all_commitment_aggregated_signature: UInt768(*self.all_commitment_aggregated_signature),
            signers_count: encode::VarInt(self.signers_count),
            llmq_type: self.llmq_type,
            valid_members_count: encode::VarInt(self.valid_members_count),
            signers_bitset,
            valid_members_bitset,
            entry_hash: UInt256(*self.entry_hash),
            verified: self.verified,
            saved: self.saved,
            commitment_hash: if self.commitment_hash.is_null() {
                None
            } else {
                Some(UInt256(*self.commitment_hash))
            },
        }
    }
}

impl<'a> FromFFI<'a> for types::MNListDiff {
    type Item = mn_list_diff::MNListDiff;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            base_block_hash: UInt256(*self.base_block_hash),
            block_hash: UInt256(*self.block_hash),
            total_transactions: self.total_transactions,
            // merkle_hashes: slice::from_raw_parts(self.merkle_hashes, self.merkle_hashes_count),
            // merkle_hashes_count: self.merkle_hashes_count,
            merkle_hashes: VarArray::new(
                VarInt(self.merkle_hashes_count as u64),
                (0..self.merkle_hashes_count)
                    .into_iter()
                    .map(|i| UInt256(*(*self.merkle_hashes.offset(i as isize))))
                    .collect(),
            ),
            merkle_flags: slice::from_raw_parts(self.merkle_flags, self.merkle_flags_count).to_vec(),
            // merkle_flags_count: self.merkle_flags_count,
            coinbase_transaction: (*self.coinbase_transaction).decode(),
            deleted_masternode_hashes: (0..self.deleted_masternode_hashes_count)
                .into_iter()
                .map(|i| UInt256(*(*self.deleted_masternode_hashes.offset(i as isize))))
                .collect(),
            added_or_modified_masternodes: (0..self.added_or_modified_masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let value =
                        (*(*(self.added_or_modified_masternodes.offset(i as isize)))).decode();
                    let key = value
                        .provider_registration_transaction_hash
                        .clone()
                        .reversed();
                    acc.insert(key, value);
                    acc
                }),
            deleted_quorums: (0..self.deleted_quorums_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let obj = *(*(self.deleted_quorums.offset(i as isize)));
                    acc.entry(LLMQType::from(obj.llmq_type))
                        .or_insert(Vec::new())
                        .push(UInt256(*obj.llmq_hash));
                    acc
                },
            ),
            added_quorums: (0..self.added_quorums_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let entry = (*(*(self.added_quorums.offset(i as isize)))).decode();
                    acc.entry(entry.llmq_type)
                        .or_insert(BTreeMap::new())
                        .insert(entry.llmq_hash, entry);
                    acc
                },
            ),
            block_height: self.block_height,
        }
    }
}
impl<'a> FromFFI<'a> for types::LLMQSnapshot {
    type Item = snapshot::LLMQSnapshot;

    unsafe fn decode(&self) -> Self::Item {
        let member_list_bytes =
            slice::from_raw_parts::<u8>(self.member_list, self.member_list_length);
        let skip_list_bytes = slice::from_raw_parts::<i32>(self.skip_list, self.skip_list_length);
        Self::Item {
            member_list: member_list_bytes.to_vec(),
            skip_list: skip_list_bytes.to_vec(),
            skip_list_mode: self.skip_list_mode,
        }
        /*Self::Item {
            member_list: (0..self.member_list_length)
                .into_iter()
                .map(|i| *(self.member_list.offset(i as isize)))
                .collect(),
            skip_list: (0..self.skip_list_length)
                .into_iter()
                .map(|i| *(self.skip_list.offset(i as isize)))
                .collect(),
            skip_list_mode: self.skip_list_mode
        }*/
    }
}

impl<'a> FromFFI<'a> for types::QRInfo {
    type Item = rotation_info::LLMQRotationInfo;

    unsafe fn decode(&self) -> Self::Item {
        let extra_share = self.extra_share;
        let (snapshot_at_h_4c, mn_list_diff_at_h_4c) = if extra_share {
            (
                Some((*self.snapshot_at_h_4c).decode()),
                Some((*self.mn_list_diff_at_h_4c).decode()),
            )
        } else {
            (None, None)
        };
        Self::Item {
            snapshot_at_h_c: (*self.snapshot_at_h_c).decode(),
            snapshot_at_h_2c: (*self.snapshot_at_h_2c).decode(),
            snapshot_at_h_3c: (*self.snapshot_at_h_3c).decode(),
            mn_list_diff_tip: (*self.mn_list_diff_tip).decode(),
            mn_list_diff_at_h: (*self.mn_list_diff_at_h).decode(),
            mn_list_diff_at_h_c: (*self.mn_list_diff_at_h_c).decode(),
            mn_list_diff_at_h_2c: (*self.mn_list_diff_at_h_2c).decode(),
            mn_list_diff_at_h_3c: (*self.mn_list_diff_at_h_3c).decode(),
            extra_share,
            snapshot_at_h_4c,
            mn_list_diff_at_h_4c,
            last_quorum_per_index: (0..self.last_quorum_per_index_count)
                .into_iter()
                .map(|i| (*(*self.last_quorum_per_index.offset(i as isize))).decode())
                .collect(),
            quorum_snapshot_list: (0..self.quorum_snapshot_list_count)
                .into_iter()
                .map(|i| (*(*self.quorum_snapshot_list.offset(i as isize))).decode())
                .collect(),
            mn_list_diff_list: (0..self.mn_list_diff_list_count)
                .into_iter()
                .map(|i| (*(*self.mn_list_diff_list.offset(i as isize))).decode())
                .collect(),
        }
    }
}

impl<'a> FromFFI<'a> for types::Block {
    type Item = common::Block;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            height: self.height,
            hash: UInt256(*self.hash),
        }
    }
}
