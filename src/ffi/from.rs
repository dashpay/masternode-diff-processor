use std::collections::BTreeMap;
use std::slice;
use crate::{common, encode, models, tx, types};
use crate::crypto::{UInt128, UInt160, UInt256, UInt384, UInt768};
use crate::crypto::byte_util::Reversable;
use crate::ffi::to::ToFFI;
use crate::tx::transaction;

pub trait FromFFI {
    type Item: ToFFI;
    /// # Safety
    unsafe fn decode(&self) -> Self::Item;
}
impl FromFFI for types::TransactionInput {
    type Item = transaction::TransactionInput;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            input_hash: UInt256(*self.input_hash),
            index: self.index,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.script, self.script_length).to_vec())
            },
            signature: if self.signature.is_null() || self.signature_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.signature, self.signature_length).to_vec())
            },
            sequence: self.sequence,
        }
    }
}

impl FromFFI for types::TransactionOutput {
    type Item = transaction::TransactionOutput;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            amount: self.amount,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.script, self.script_length).to_vec())
            },
            address: if self.address.is_null() || self.address_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.address, self.address_length).to_vec())
            },
        }
    }
}
impl FromFFI for types::Transaction {
    type Item = tx::Transaction;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            inputs: (0..self.inputs_count)
                .into_iter()
                .map(|i| (*(*self.inputs.add(i))).decode())
                .collect(),
            outputs: (0..self.outputs_count)
                .into_iter()
                .map(|i| (*(*self.outputs.add(i))).decode())
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
impl FromFFI for types::CoinbaseTransaction {
    type Item = tx::CoinbaseTransaction;

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

impl FromFFI for types::MasternodeList {
    type Item = models::MasternodeList;

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
                    let value = (*(*self.masternodes.add(i))).decode();
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
                    let llmq_map = *(*self.llmq_type_maps.add(i));
                    let key = common::LLMQType::from(llmq_map.llmq_type);
                    let value: BTreeMap<UInt256, models::LLMQEntry> = (0..llmq_map.count)
                        .into_iter()
                        .fold(BTreeMap::new(), |mut acc, j| {
                            let raw_value = *(*llmq_map.values.add(j));
                            let value = raw_value.decode();
                            let key = value.llmq_hash;
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

impl FromFFI for types::OperatorPublicKey {
    type Item = models::OperatorPublicKey;
    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            data: UInt384(self.data),
            version: self.version
        }
    }
}

impl FromFFI for types::MasternodeEntry {
    type Item = models::MasternodeEntry;
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
            socket_address: common::SocketAddress {
                ip_address: UInt128(*self.ip_address),
                port: self.port,
            },
            operator_public_key: (*self.operator_public_key).decode(),
            previous_operator_public_keys: (0..self.previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_operator_public_keys.add(i);
                    let key = common::Block {
                        height: obj.block_height,
                        hash: UInt256(obj.block_hash),
                    };
                    let value = models::OperatorPublicKey {
                        data: UInt384(obj.key),
                        version: obj.version
                    };
                    acc.insert(key, value);
                    acc
                }),
            previous_entry_hashes: (0..self.previous_entry_hashes_count).into_iter().fold(
                BTreeMap::new(),
                |mut acc, i| {
                    let obj = *self.previous_entry_hashes.add(i);
                    let key = common::Block {
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
                    let obj = *self.previous_validity.add(i);
                    let key = common::Block {
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

impl FromFFI for types::LLMQEntry {
    type Item = models::LLMQEntry;

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
            index: if self.version.use_rotated_quorums() { Some(self.index) } else { None },
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

// impl FromFFI for types::MNListDiff {
//     type Item = models::MNListDiff;
//
//     unsafe fn decode(&self) -> Self::Item {
//         Self::Item {
//             base_block_hash: UInt256(*self.base_block_hash),
//             block_hash: UInt256(*self.block_hash),
//             total_transactions: self.total_transactions,
//             merkle_hashes: (0..self.merkle_hashes_count)
//                 .into_iter()
//                 .map(|i| UInt256(*(*self.merkle_hashes.add(i))))
//                 .collect(),
//             merkle_flags: slice::from_raw_parts(self.merkle_flags, self.merkle_flags_count).to_vec(),
//             coinbase_transaction: (*self.coinbase_transaction).decode(),
//             deleted_masternode_hashes: (0..self.deleted_masternode_hashes_count)
//                 .into_iter()
//                 .map(|i| UInt256(*(*self.deleted_masternode_hashes.add(i))))
//                 .collect(),
//             added_or_modified_masternodes: (0..self.added_or_modified_masternodes_count)
//                 .into_iter()
//                 .fold(BTreeMap::new(), |mut acc, i| {
//                     let value =
//                         (*(*self.added_or_modified_masternodes.add(i))).decode();
//                     let key = value
//                         .provider_registration_transaction_hash
//                         .clone()
//                         .reversed();
//                     acc.insert(key, value);
//                     acc
//                 }),
//             deleted_quorums: (0..self.deleted_quorums_count).into_iter().fold(
//                 BTreeMap::new(),
//                 |mut acc, i| {
//                     let obj = *(*self.deleted_quorums.add(i));
//                     acc.entry(common::LLMQType::from(obj.llmq_type))
//                         .or_insert_with(Vec::new)
//                         .push(UInt256(*obj.llmq_hash));
//                     acc
//                 },
//             ),
//             added_quorums: (0..self.added_quorums_count).into_iter().fold(
//                 BTreeMap::new(),
//                 |mut acc, i| {
//                     let entry = (*(*self.added_quorums.add(i))).decode();
//                     acc.entry(entry.llmq_type)
//                         .or_insert_with(BTreeMap::new)
//                         .insert(entry.llmq_hash, entry);
//                     acc
//                 },
//             ),
//             base_block_height: self.base_block_height,
//             block_height: self.block_height,
//         }
//     }
// }
impl FromFFI for types::LLMQSnapshot {
    type Item = models::LLMQSnapshot;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            member_list: slice::from_raw_parts(self.member_list, self.member_list_length).to_vec(),
            skip_list: slice::from_raw_parts::<i32>(self.skip_list, self.skip_list_length).to_vec(),
            skip_list_mode: self.skip_list_mode,
        }
    }
}

// impl FromFFI for types::QRInfo {
//     type Item = models::LLMQRotationInfo;
//
//     unsafe fn decode(&self) -> Self::Item {
//         let extra_share = self.extra_share;
//         let (snapshot_at_h_4c, mn_list_diff_at_h_4c) = if extra_share {
//             (
//                 Some((*self.snapshot_at_h_4c).decode()),
//                 Some((*self.mn_list_diff_at_h_4c).decode()),
//             )
//         } else {
//             (None, None)
//         };
//         Self::Item {
//             snapshot_at_h_c: (*self.snapshot_at_h_c).decode(),
//             snapshot_at_h_2c: (*self.snapshot_at_h_2c).decode(),
//             snapshot_at_h_3c: (*self.snapshot_at_h_3c).decode(),
//             mn_list_diff_tip: (*self.mn_list_diff_tip).decode(),
//             mn_list_diff_at_h: (*self.mn_list_diff_at_h).decode(),
//             mn_list_diff_at_h_c: (*self.mn_list_diff_at_h_c).decode(),
//             mn_list_diff_at_h_2c: (*self.mn_list_diff_at_h_2c).decode(),
//             mn_list_diff_at_h_3c: (*self.mn_list_diff_at_h_3c).decode(),
//             extra_share,
//             snapshot_at_h_4c,
//             mn_list_diff_at_h_4c,
//             last_quorum_per_index: (0..self.last_quorum_per_index_count)
//                 .into_iter()
//                 .map(|i| (*(*self.last_quorum_per_index.add(i))).decode())
//                 .collect(),
//             quorum_snapshot_list: (0..self.quorum_snapshot_list_count)
//                 .into_iter()
//                 .map(|i| (*(*self.quorum_snapshot_list.add(i))).decode())
//                 .collect(),
//             mn_list_diff_list: (0..self.mn_list_diff_list_count)
//                 .into_iter()
//                 .map(|i| (*(*self.mn_list_diff_list.add(i))).decode())
//                 .collect(),
//         }
//     }
// }

impl FromFFI for types::Block {
    type Item = common::Block;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            height: self.height,
            hash: UInt256(*self.hash),
        }
    }
}
