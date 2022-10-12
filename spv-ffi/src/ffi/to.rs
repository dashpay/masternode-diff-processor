use crate::ffi::boxer::{boxed, boxed_vec};
use crate::ffi::from::FromFFI;
use crate::types;
use dash_spv_models::common;
use dash_spv_models::common::{Block, LLMQType};
use dash_spv_models::llmq::{mn_list_diff, rotation_info, snapshot};
use dash_spv_models::masternode::{llmq_entry, masternode_entry, masternode_list};
use dash_spv_models::tx::{coinbase_transaction, transaction};
use dash_spv_primitives::crypto::byte_util::UInt256;
use std::collections::BTreeMap;
use std::ptr::null_mut;

pub trait ToFFI<'a> {
    type Item: FromFFI<'a>;
    fn encode(&self) -> Self::Item;
}
impl<'a> ToFFI<'a> for transaction::TransactionInput {
    type Item = types::TransactionInput;

    fn encode(&self) -> Self::Item {
        let (script, script_length) = match &self.script {
            Some(data) => (boxed_vec(data.clone()), data.len()),
            None => (null_mut(), 0),
        };
        let (signature, signature_length) = match &self.signature {
            Some(data) => (boxed_vec(data.clone()), data.len()),
            None => (null_mut(), 0),
        };
        Self::Item {
            input_hash: boxed(self.input_hash.0),
            index: self.index,
            script,
            script_length,
            signature,
            signature_length,
            sequence: self.sequence,
        }
    }
}

impl<'a> ToFFI<'a> for transaction::TransactionOutput {
    type Item = types::TransactionOutput;

    fn encode(&self) -> Self::Item {
        let (script, script_length) = match &self.script {
            Some(data) => (boxed_vec(data.clone()), data.len()),
            None => (null_mut(), 0),
        };
        let (address, address_length) = match &self.address {
            Some(data) => (boxed_vec(data.clone()), data.len()),
            None => (null_mut(), 0),
        };
        Self::Item {
            amount: self.amount,
            script,
            script_length,
            address,
            address_length,
        }
    }
}

impl<'a> ToFFI<'a> for transaction::Transaction {
    type Item = types::Transaction;

    fn encode(&self) -> Self::Item {
        Self::Item {
            inputs: boxed_vec(
                self.inputs
                    .iter()
                    .map(|input| boxed(input.encode()))
                    .collect(),
            ),
            inputs_count: self.inputs.len(),
            outputs: boxed_vec(
                self.outputs
                    .iter()
                    .map(|output| boxed(output.encode()))
                    .collect(),
            ),
            outputs_count: self.outputs.len(),
            lock_time: self.lock_time,
            version: self.version,
            tx_hash: if self.tx_hash.is_none() {
                null_mut()
            } else {
                boxed(self.tx_hash.unwrap().0)
            },
            tx_type: self.tx_type,
            payload_offset: self.payload_offset,
            block_height: self.block_height,
        }
    }
}
impl<'a> ToFFI<'a> for coinbase_transaction::CoinbaseTransaction {
    type Item = types::CoinbaseTransaction;

    fn encode(&self) -> Self::Item {
        Self::Item {
            base: boxed(self.base.encode()),
            coinbase_transaction_version: self.coinbase_transaction_version,
            height: self.height,
            merkle_root_mn_list: boxed(self.merkle_root_mn_list.0),
            merkle_root_llmq_list: if self.merkle_root_llmq_list.is_none() {
                null_mut()
            } else {
                boxed(self.merkle_root_llmq_list.unwrap().0)
            },
        }
    }
}

impl<'a> ToFFI<'a> for masternode_list::MasternodeList {
    type Item = types::MasternodeList;

    fn encode(&self) -> Self::Item {
        Self::Item {
            block_hash: boxed(self.block_hash.0),
            known_height: self.known_height,
            masternode_merkle_root: if self.masternode_merkle_root.is_none() {
                null_mut()
            } else {
                boxed(self.masternode_merkle_root.unwrap().0)
            },
            llmq_merkle_root: if self.llmq_merkle_root.is_none() {
                null_mut()
            } else {
                boxed(self.llmq_merkle_root.unwrap().0)
            },
            masternodes: encode_masternodes_map(&self.masternodes),
            masternodes_count: self.masternodes.len(),
            llmq_type_maps: encode_quorums_map(&self.quorums),
            llmq_type_maps_count: self.quorums.len(),
        }
    }
}

impl<'a> ToFFI<'a> for masternode_entry::MasternodeEntry {
    type Item = types::MasternodeEntry;

    fn encode(&self) -> Self::Item {
        let previous_operator_public_keys_count = self.previous_operator_public_keys.len();
        let previous_entry_hashes_count = self.previous_entry_hashes.len();
        let previous_validity_count = self.previous_validity.len();
        let confirmed_hash = boxed(self.confirmed_hash.0);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if self
            .confirmed_hash_hashed_with_provider_registration_transaction_hash
            .is_none()
        {
            null_mut()
        } else {
            boxed(
                self.confirmed_hash_hashed_with_provider_registration_transaction_hash
                    .unwrap()
                    .0,
            )
        };
        let key_id_voting = boxed(self.key_id_voting.0);
        let known_confirmed_at_height = self.known_confirmed_at_height.unwrap_or(0);
        let entry_hash = boxed(self.entry_hash.0);
        let operator_public_key = boxed(self.operator_public_key.0);
        let previous_operator_public_keys = boxed_vec(
            self.previous_operator_public_keys
                .iter()
                .map(
                    |(
                        &Block {
                            hash,
                            height: block_height,
                        },
                        &key,
                    )| types::OperatorPublicKey {
                        block_hash: hash.0,
                        block_height,
                        key: key.0,
                    },
                )
                .collect(),
        );
        let previous_entry_hashes = boxed_vec(
            self.previous_entry_hashes
                .iter()
                .map(
                    |(
                        &Block {
                            hash: block_hash,
                            height: block_height,
                        },
                        &hash,
                    )| types::MasternodeEntryHash {
                        block_hash: block_hash.0,
                        block_height,
                        hash: hash.0,
                    },
                )
                .collect(),
        );
        let previous_validity = boxed_vec(
            self.previous_validity
                .iter()
                .map(
                    |(
                        &Block {
                            hash,
                            height: block_height,
                        },
                        &is_valid,
                    )| types::Validity {
                        block_hash: hash.0,
                        block_height,
                        is_valid,
                    },
                )
                .collect(),
        );
        let provider_registration_transaction_hash =
            boxed(self.provider_registration_transaction_hash.0);
        let ip_address = boxed(self.socket_address.ip_address.0);
        let port = self.socket_address.port;
        let is_valid = self.is_valid;
        let update_height = self.update_height;
        Self::Item {
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash,
            is_valid,
            key_id_voting,
            known_confirmed_at_height,
            entry_hash,
            operator_public_key,
            previous_operator_public_keys,
            previous_operator_public_keys_count,
            previous_entry_hashes,
            previous_entry_hashes_count,
            previous_validity,
            previous_validity_count,
            provider_registration_transaction_hash,
            ip_address,
            port,
            update_height,
        }
    }
}

impl<'a> ToFFI<'a> for llmq_entry::LLMQEntry {
    type Item = types::LLMQEntry;

    fn encode(&self) -> Self::Item {
        let all_commitment_aggregated_signature = boxed(self.all_commitment_aggregated_signature.0);
        let commitment_hash = if self.commitment_hash.is_none() {
            null_mut()
        } else {
            boxed(self.commitment_hash.unwrap().0)
        };
        let llmq_type = self.llmq_type;
        let entry_hash = boxed(self.entry_hash.0);
        let llmq_hash = boxed(self.llmq_hash.0);
        let public_key = boxed(self.public_key.0);
        let threshold_signature = boxed(self.threshold_signature.0);
        let verification_vector_hash = boxed(self.verification_vector_hash.0);
        let index = self.index.unwrap_or(0);
        let saved = self.saved;
        let verified = self.verified;
        let version = self.version;
        let signers_count = self.signers_count.0;
        let valid_members_count = self.valid_members_count.0;
        let signers_bitset = boxed_vec(self.signers_bitset.clone());
        let signers_bitset_length = self.signers_bitset.len();
        let valid_members_bitset = boxed_vec(self.valid_members_bitset.clone());
        let valid_members_bitset_length = self.valid_members_bitset.len();
        Self::Item {
            all_commitment_aggregated_signature,
            commitment_hash,
            llmq_type,
            entry_hash,
            llmq_hash,
            index,
            public_key,
            threshold_signature,
            verification_vector_hash,
            saved,
            signers_bitset,
            signers_bitset_length,
            signers_count,
            valid_members_bitset,
            valid_members_bitset_length,
            valid_members_count,
            verified,
            version,
        }
    }
}

impl<'a> ToFFI<'a> for mn_list_diff::MNListDiff {
    type Item = types::MNListDiff;

    fn encode(&self) -> Self::Item {
        let deleted_masternode_hashes_count = self.deleted_masternode_hashes.len();
        let deleted_quorums_vec = self.deleted_quorums.clone().into_iter().fold(
            Vec::new(),
            |mut acc, (llmq_type, hashes)| {
                hashes.iter().for_each(|&hash| {
                    acc.push(boxed(types::LLMQTypedHash {
                        llmq_hash: boxed(hash.0),
                        llmq_type: llmq_type.into(),
                    }))
                });
                acc
            },
        );
        let added_quorums_vec =
            self.added_quorums
                .clone()
                .into_iter()
                .fold(Vec::new(), |mut acc, (_, map)| {
                    map.iter()
                        .for_each(|(_, entry)| acc.push(boxed(entry.encode())));
                    acc
                });
        Self::Item {
            base_block_hash: boxed(self.base_block_hash.0),
            block_hash: boxed(self.block_hash.0),
            total_transactions: self.total_transactions,
            merkle_hashes: boxed_vec(
                (0..self.merkle_hashes.1.len())
                    .into_iter()
                    .map(|i| boxed(self.merkle_hashes.1[i].0))
                    .collect(),
            ),
            merkle_hashes_count: self.merkle_hashes.1.len(),
            merkle_flags: boxed_vec(self.merkle_flags.to_vec()),
            merkle_flags_count: self.merkle_flags.len(),
            coinbase_transaction: boxed(self.coinbase_transaction.encode()),
            deleted_masternode_hashes_count,
            deleted_masternode_hashes: boxed_vec(
                (0..deleted_masternode_hashes_count)
                    .into_iter()
                    .map(|i| boxed(self.deleted_masternode_hashes[i].0))
                    .collect(),
            ),
            added_or_modified_masternodes_count: self.added_or_modified_masternodes.len(),
            added_or_modified_masternodes: encode_masternodes_map(
                &self.added_or_modified_masternodes,
            ),
            deleted_quorums_count: deleted_quorums_vec.len(),
            deleted_quorums: boxed_vec(deleted_quorums_vec),
            added_quorums_count: added_quorums_vec.len(),
            added_quorums: boxed_vec(added_quorums_vec),
            block_height: self.block_height,
        }
    }
}
impl<'a> ToFFI<'a> for snapshot::LLMQSnapshot {
    type Item = types::LLMQSnapshot;

    fn encode(&self) -> Self::Item {
        Self::Item {
            member_list_length: self.member_list.len(),
            member_list: boxed_vec(self.member_list.clone()),
            skip_list_length: self.skip_list.len(),
            skip_list: boxed_vec(self.skip_list.to_vec()),
            skip_list_mode: self.skip_list_mode,
        }
    }
}

impl<'a> ToFFI<'a> for rotation_info::LLMQRotationInfo {
    type Item = types::QRInfo;

    fn encode(&self) -> Self::Item {
        let snapshot_at_h_c = boxed(self.snapshot_at_h_c.encode());
        let snapshot_at_h_2c = boxed(self.snapshot_at_h_2c.encode());
        let snapshot_at_h_3c = boxed(self.snapshot_at_h_3c.encode());
        let mn_list_diff_tip = boxed(self.mn_list_diff_tip.encode());
        let mn_list_diff_at_h = boxed(self.mn_list_diff_at_h.encode());
        let mn_list_diff_at_h_c = boxed(self.mn_list_diff_at_h_c.encode());
        let mn_list_diff_at_h_2c = boxed(self.mn_list_diff_at_h_2c.encode());
        let mn_list_diff_at_h_3c = boxed(self.mn_list_diff_at_h_3c.encode());
        let extra_share = self.extra_share;
        let (snapshot_at_h_4c, mn_list_diff_at_h_4c) = if extra_share {
            (
                boxed(self.snapshot_at_h_4c.as_ref().unwrap().encode()),
                boxed(self.mn_list_diff_at_h_4c.as_ref().unwrap().encode()),
            )
        } else {
            (null_mut(), null_mut())
        };
        let last_quorum_per_index_count = self.last_quorum_per_index.len();
        let last_quorum_per_index = boxed_vec(
            (0..last_quorum_per_index_count)
                .into_iter()
                .map(|i| boxed(self.last_quorum_per_index[i].encode()))
                .collect(),
        );
        let quorum_snapshot_list_count = self.quorum_snapshot_list.len();
        let quorum_snapshot_list = boxed_vec(
            (0..quorum_snapshot_list_count)
                .into_iter()
                .map(|i| boxed(self.quorum_snapshot_list[i].encode()))
                .collect(),
        );
        let mn_list_diff_list_count = self.mn_list_diff_list.len();
        let mn_list_diff_list = boxed_vec(
            (0..mn_list_diff_list_count)
                .into_iter()
                .map(|i| boxed(self.mn_list_diff_list[i].encode()))
                .collect(),
        );
        Self::Item {
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            mn_list_diff_tip,
            mn_list_diff_at_h,
            mn_list_diff_at_h_c,
            mn_list_diff_at_h_2c,
            mn_list_diff_at_h_3c,
            extra_share,
            snapshot_at_h_4c,
            mn_list_diff_at_h_4c,
            last_quorum_per_index_count,
            last_quorum_per_index,
            quorum_snapshot_list_count,
            quorum_snapshot_list,
            mn_list_diff_list_count,
            mn_list_diff_list,
        }
    }
}

impl<'a> ToFFI<'a> for common::Block {
    type Item = types::Block;

    fn encode(&self) -> Self::Item {
        Self::Item {
            height: self.height,
            hash: boxed(self.hash.0),
        }
    }
}

pub fn encode_quorums_map(
    quorums: &BTreeMap<LLMQType, BTreeMap<UInt256, llmq_entry::LLMQEntry>>,
) -> *mut *mut types::LLMQMap {
    boxed_vec(
        quorums
            .iter()
            .map(|(&llmq_type, map)| {
                boxed(types::LLMQMap {
                    llmq_type: llmq_type.into(),
                    values: boxed_vec(
                        (*map)
                            .iter()
                            .map(|(_, entry)| boxed(entry.encode()))
                            .collect(),
                    ),
                    count: (*map).len(),
                })
            })
            .collect(),
    )
}

pub fn encode_masternodes_map(
    masternodes: &BTreeMap<UInt256, masternode_entry::MasternodeEntry>,
) -> *mut *mut types::MasternodeEntry {
    boxed_vec(
        masternodes
            .iter()
            .map(|(_, entry)| boxed((*entry).encode()))
            .collect(),
    )
}
