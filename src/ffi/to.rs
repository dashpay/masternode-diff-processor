use std::collections::{BTreeMap, HashMap};
use std::ptr::null_mut;
use dash_spv_models::common::block_data::BlockData;
use dash_spv_models::masternode::{llmq_entry, masternode_entry, masternode_list};
use dash_spv_models::tx::{coinbase_transaction, transaction};
use dash_spv_primitives::crypto::byte_util::UInt256;
use crate::{ffi, LLMQType};
use crate::ffi::boxer::{boxed, boxed_vec};
use crate::ffi::from::FromFFI;
use crate::processing::{mn_list_diff, llmq_rotation_info, llmq_snapshot};

pub trait ToFFI<'a> {
    type Item: FromFFI<'a>;
    fn encode(&self) -> Self::Item;
}
impl<'a> ToFFI<'a> for transaction::TransactionInput<'a> {
    type Item = ffi::types::TransactionInput;

    fn encode(&self) -> Self::Item {
        let (script, script_length) = if self.script.is_none() {
            (null_mut(), 0)
        } else {
            let s = self.script.unwrap();
            (boxed_vec(s.to_vec()), s.len())
        };
        let (signature, signature_length) = if self.signature.is_none() {
            (null_mut(), 0)
        } else {
            let s = self.signature.unwrap();
            (boxed_vec(s.to_vec()), s.len())
        };
        Self::Item {
            input_hash: boxed(self.input_hash.0),
            index: self.index,
            script,
            script_length,
            signature,
            signature_length,
            sequence: self.sequence
        }
    }
}

impl<'a> ToFFI<'a> for transaction::TransactionOutput<'a> {
    type Item = ffi::types::TransactionOutput;

    fn encode(&self) -> Self::Item {
        let (script, script_length) = if self.script.is_none() {
            (null_mut(), 0)
        } else {
            let s = self.script.unwrap();
            (boxed_vec(s.to_vec()), s.len())
        };
        let (address, address_length) = if self.address.is_none() {
            (null_mut(), 0)
        } else {
            let s = self.address.unwrap();
            (boxed_vec(s.to_vec()), s.len())
        };
        Self::Item {
            amount: self.amount,
            script,
            script_length,
            address,
            address_length
        }
    }
}

impl<'a> ToFFI<'a> for transaction::Transaction<'a> {
    type Item = ffi::types::Transaction;

    fn encode(&self) -> Self::Item {
        Self::Item {
            inputs: boxed_vec(self.inputs
                .iter()
                .map(|&input| boxed(input.encode()))
                .collect()),
            inputs_count: self.inputs.len(),
            outputs: boxed_vec(self.outputs
                .iter()
                .map(|&output| boxed(output.encode()))
                .collect()),
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
            block_height: self.block_height
        }
    }
}
impl<'a> ToFFI<'a> for coinbase_transaction::CoinbaseTransaction<'a> {
    type Item = ffi::types::CoinbaseTransaction;

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
            }
        }
    }
}

impl<'a> ToFFI<'a> for masternode_list::MasternodeList<'a> {
    type Item = ffi::types::MasternodeList;

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
            llmq_type_maps_count: self.quorums.len()
        }
    }
}

impl<'a> ToFFI<'a> for masternode_entry::MasternodeEntry {
    type Item = ffi::types::MasternodeEntry;

    fn encode(&self) -> Self::Item {
        let previous_operator_public_keys_count = self.previous_operator_public_keys.len();
        let previous_entry_hashes_count = self.previous_entry_hashes.len();
        let previous_validity_count = self.previous_validity.len();
        Self::Item {
            confirmed_hash: boxed(self.confirmed_hash.0),
            confirmed_hash_hashed_with_provider_registration_transaction_hash: if self.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_none() {
                null_mut()
            } else {
                boxed(self.confirmed_hash_hashed_with_provider_registration_transaction_hash.unwrap().0)
            },
            is_valid: self.is_valid,
            key_id_voting: boxed(self.key_id_voting.0),
            known_confirmed_at_height: self.known_confirmed_at_height.unwrap_or(0),
            entry_hash: boxed(self.entry_hash.0),
            operator_public_key: boxed(self.operator_public_key.0),
            previous_operator_public_keys: boxed_vec(self.previous_operator_public_keys
                .iter()
                .map(|(&BlockData {hash, height: block_height}, &key)|
                    ffi::types::OperatorPublicKey { block_hash: hash.0, block_height, key: key.0 })
                .collect()),
            previous_operator_public_keys_count,
            previous_entry_hashes: boxed_vec(self.previous_entry_hashes
                .iter()
                .map(|(&BlockData { hash: block_hash, height: block_height}, &hash)|
                    ffi::types::MasternodeEntryHash { block_hash: block_hash.0, block_height, hash: hash.0 })
                .collect()),
            previous_entry_hashes_count,
            previous_validity: boxed_vec(self.previous_validity
                .iter()
                .map(|(&BlockData { hash, height: block_height}, &is_valid)|
                    ffi::types::Validity { block_hash: hash.0, block_height, is_valid })
                .collect()),
            previous_validity_count,
            provider_registration_transaction_hash: boxed(self.provider_registration_transaction_hash.0),
            ip_address: boxed(self.socket_address.ip_address.0),
            port: self.socket_address.port,
            update_height: self.update_height
        }
    }
}

impl<'a> ToFFI<'a> for llmq_entry::LLMQEntry<'a> {
    type Item = ffi::types::LLMQEntry;

    fn encode(&self) -> Self::Item {
        //println!("LLMQEntry.to: {:?} {} {}", self.entry_hash, self.signers_bitset.to_hex(), self.signers_bitset.len());
        Self::Item {
            all_commitment_aggregated_signature: boxed(self.all_commitment_aggregated_signature.0),
            commitment_hash: if self.commitment_hash.is_none() {
                null_mut()
            } else {
                boxed(self.commitment_hash.unwrap().0)
            },
            length: self.length,
            llmq_type: self.llmq_type,
            entry_hash: boxed(self.entry_hash.0),
            llmq_hash: boxed(self.llmq_hash.0),
            index: self.index.unwrap_or(0),
            public_key: boxed(self.public_key.0),
            threshold_signature: boxed(self.threshold_signature.0),
            verification_vector_hash: boxed(self.verification_vector_hash.0),
            saved: self.saved,
            signers_bitset: boxed_vec(self.signers_bitset.to_vec()),
            signers_bitset_length: self.signers_bitset.len(),
            signers_count: self.signers_count.0,
            valid_members_bitset: boxed_vec(self.valid_members_bitset.to_vec()),
            valid_members_bitset_length: self.valid_members_bitset.len(),
            valid_members_count: self.valid_members_count.0,
            verified: self.verified,
            version: self.version,
        }
    }
}

impl<'a> ToFFI<'a> for mn_list_diff::MNListDiff<'a> {
    type Item = ffi::types::MNListDiff;

    fn encode(&self) -> Self::Item {
        let deleted_masternode_hashes_count = self.deleted_masternode_hashes.len();
        let deleted_quorums_vec = self.deleted_quorums
            .clone()
            .into_iter()
            .fold(Vec::new(), |mut acc, (llmq_type, hashes)| {
                hashes
                    .iter()
                    .for_each(|&hash| acc.push(boxed(ffi::types::LLMQTypedHash { llmq_hash: boxed(hash.0), llmq_type: llmq_type.into() })));
                acc
            });
        let added_quorums_vec = self.added_quorums
            .clone()
            .into_iter()
            .fold(Vec::new(), |mut acc, (_, map)| {
                map
                    .iter()
                    .for_each(|(_, &entry)| acc.push(boxed(entry.encode())));
                acc
            });
        Self::Item {
            base_block_hash: boxed(self.base_block_hash.0),
            block_hash: boxed(self.block_hash.0),
            total_transactions: self.total_transactions,
            merkle_hashes: boxed_vec(self.merkle_hashes.to_vec()),
            merkle_hashes_count: self.merkle_hashes.len(),
            merkle_flags: boxed_vec(self.merkle_flags.to_vec()),
            merkle_flags_count: self.merkle_flags.len(),
            coinbase_transaction: boxed(self.coinbase_transaction.encode()),
            deleted_masternode_hashes_count,
            deleted_masternode_hashes: boxed_vec((0..deleted_masternode_hashes_count)
                .into_iter()
                .map(|i| boxed(self.deleted_masternode_hashes[i].0))
                .collect()),
            added_or_modified_masternodes_count: self.added_or_modified_masternodes.len(),
            added_or_modified_masternodes: encode_masternodes_map(&self.added_or_modified_masternodes),
            deleted_quorums_count: deleted_quorums_vec.len(),
            deleted_quorums: boxed_vec(deleted_quorums_vec),
            added_quorums_count: added_quorums_vec.len(),
            added_quorums: boxed_vec(added_quorums_vec),
            length: self.length,
            block_height: self.block_height
        }
    }
}
impl<'a> ToFFI<'a> for llmq_snapshot::LLMQSnapshot<'a> {
    type Item = ffi::types::LLMQSnapshot;

    fn encode(&self) -> Self::Item {
        let member_list_length = self.member_list.len();
        let member_list = boxed_vec(self.member_list.to_vec());
        let skip_list_length = self.skip_list.len();
        let skip_list = boxed_vec(self.skip_list.to_vec());
        let skip_list_mode = self.skip_list_mode;
        Self::Item {
            member_list_length,
            member_list,
            skip_list_length,
            skip_list,
            skip_list_mode
        }
    }
}

impl<'a> ToFFI<'a> for llmq_rotation_info::LLMQRotationInfo<'a> {
    type Item = ffi::types::LLMQRotationInfo;

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
            (boxed(self.snapshot_at_h_4c.as_ref().unwrap().encode()),
             boxed(self.mn_list_diff_at_h_4c.as_ref().unwrap().encode()))
        } else {
            (null_mut(), null_mut())
        };
        /*let block_hash_list_num = self.block_hash_list.len();
        let block_hash_list = boxed_vec(
            (0..block_hash_list_num)
                .into_iter()
                .map(|i| boxed(self.block_hash_list[i].0))
                .collect());
        let snapshot_list_num = self.snapshot_list.len();
        let snapshot_list = boxed_vec(
            (0..snapshot_list_num)
                .into_iter()
                .map(|i| boxed(self.snapshot_list[i].encode()))
                .collect());
        let mn_list_diff_list_num = self.mn_list_diff_list.len();
        let mn_list_diff_list = boxed_vec(
            (0..mn_list_diff_list_num)
                .into_iter()
                .map(|i| boxed(self.mn_list_diff_list[i].encode()))
                .collect());*/
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
            /*block_hash_list_num: block_hash_list_num as u32,
            block_hash_list,
            snapshot_list_num: snapshot_list_num as u32,
            snapshot_list,
            mn_list_diff_list_num: mn_list_diff_list_num as u32,
            mn_list_diff_list*/
        }
    }
}

pub fn encode_quorums_map(quorums: &HashMap<LLMQType, HashMap<UInt256, llmq_entry::LLMQEntry>>) -> *mut *mut ffi::types::LLMQMap {
    boxed_vec(quorums
        .iter()
        .map(|(&llmq_type, map)|
            boxed(ffi::types::LLMQMap {
                llmq_type: llmq_type.into(),
                values: boxed_vec((*map)
                    .iter()
                    .map(|(_, &entry)| boxed(entry.encode()))
                    .collect()),
                count: (*map).len()
            }))
        .collect())
}

pub fn encode_masternodes_map(masternodes: &BTreeMap<UInt256, masternode_entry::MasternodeEntry>) -> *mut *mut ffi::types::MasternodeEntry {
    boxed_vec(masternodes
        .iter()
        .map(|(_, entry)| boxed((*entry).encode()))
        .collect())
}
