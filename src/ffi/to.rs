use std::collections::{BTreeMap, HashMap};
use std::ptr::null_mut;
use crate::common::block_data::BlockData;
use crate::common::llmq_type::LLMQType;
use crate::common::socket_address::SocketAddress;
use crate::crypto::byte_util::UInt256;
use crate::ffi::boxer::{boxed, boxed_vec};
use crate::ffi::from::FromFFI;
use crate::ffi::wrapped_types;
use crate::ffi::wrapped_types::{LLMQMap, MasternodeEntryHash, OperatorPublicKey, Validity};
use crate::masternode::{masternode_entry, masternode_list, quorum_entry};
use crate::processing::{mn_list_diff, quorum_rotation_info, quorum_snapshot};
use crate::transactions::{coinbase_transaction, transaction};
use crate::wrapped_types::LLMQTypedHash;

pub trait ToFFI<'a> {
    type Item: FromFFI<'a>;
    fn encode(&self) -> Self::Item;
}
impl<'a> ToFFI<'a> for transaction::TransactionInput<'a> {
    type Item = wrapped_types::TransactionInput;

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
    type Item = wrapped_types::TransactionOutput;

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
    type Item = wrapped_types::Transaction;

    fn encode(&self) -> Self::Item {
        let tx_hash = if self.tx_hash.is_none() {
            null_mut()
        } else {
            boxed(self.tx_hash.unwrap().0)
        };
        // let mut inputs_vec: Vec<*mut wrapped_types::TransactionInput> = Vec::with_capacity(self.inputs.len());
        // self.inputs.iter().for_each(|&input| {
        //     inputs_vec.push(boxed(input.encode()));
        // });
        let inputs_vec: Vec<*mut wrapped_types::TransactionInput> = self.inputs
            .iter()
            .map(|&input| boxed(input.encode()))
            .collect();
        let inputs = boxed_vec(inputs_vec);
        let outputs_vec = self.outputs
            .iter()
            .map(|&output| boxed(output.encode()))
            .collect();
        let outputs = boxed_vec(outputs_vec);
        wrapped_types::Transaction {
            inputs,
            inputs_count: self.inputs.len(),
            outputs,
            outputs_count: self.outputs.len(),
            lock_time: self.lock_time,
            version: self.version,
            tx_hash,
            tx_type: self.tx_type,
            payload_offset: self.payload_offset,
            block_height: self.block_height
        }
    }
}
impl<'a> ToFFI<'a> for coinbase_transaction::CoinbaseTransaction<'a> {
    type Item = wrapped_types::CoinbaseTransaction;

    fn encode(&self) -> Self::Item {
        let merkle_root_llmq_list = if self.merkle_root_llmq_list.is_none() {
            null_mut()
        } else {
            boxed(self.merkle_root_llmq_list.unwrap().0)
        };
        wrapped_types::CoinbaseTransaction {
            base: boxed(self.base.encode()),
            coinbase_transaction_version: self.coinbase_transaction_version,
            height: self.height,
            merkle_root_mn_list: boxed(self.merkle_root_mn_list.0),
            merkle_root_llmq_list
        }
    }
}

impl<'a> ToFFI<'a> for masternode_list::MasternodeList<'a> {
    type Item = wrapped_types::MasternodeList;

    fn encode(&self) -> Self::Item {
        let quorum_merkle_root = if self.quorum_merkle_root.is_none() {
            null_mut()
        } else {
            boxed(self.quorum_merkle_root.unwrap().0)
        };
        let masternode_merkle_root = if self.masternode_merkle_root.is_none() {
            null_mut()
        } else {
            boxed(self.masternode_merkle_root.unwrap().0)
        };
        let block_hash = boxed(self.block_hash.0);
        let masternodes = encode_masternodes_map(&self.masternodes);
        let quorum_type_maps = encode_quorums_map(&self.quorums);
        wrapped_types::MasternodeList {
            block_hash,
            known_height: self.known_height,
            masternode_merkle_root,
            quorum_merkle_root,
            masternodes,
            masternodes_count: self.masternodes.len(),
            quorum_type_maps,
            quorum_type_maps_count: self.quorums.len()
        }
    }
}

impl<'a> ToFFI<'a> for masternode_entry::MasternodeEntry {
    type Item = wrapped_types::MasternodeEntry;

    fn encode(&self) -> Self::Item {
        let confirmed_hash = boxed(self.confirmed_hash.0);
        let confirmed_hash_hashed_with_provider_registration_transaction_hash = if self.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_none() {
            null_mut()
        } else {
            boxed(self.confirmed_hash_hashed_with_provider_registration_transaction_hash.unwrap().0)
        };
        let is_valid = self.is_valid;
        let key_id_voting = boxed(self.key_id_voting.0);
        let known_confirmed_at_height = if self.known_confirmed_at_height.is_none() {
            0
        } else {
            self.known_confirmed_at_height.unwrap()
        };
        let masternode_entry_hash = boxed(self.masternode_entry_hash.0);
        let operator_public_key = boxed(self.operator_public_key.0);

        let previous_operator_public_keys_count = self.previous_operator_public_keys.len();
        let previous_operator_public_keys = boxed_vec(self.previous_operator_public_keys
            .iter()
            .map(|(&BlockData {hash, height: block_height}, &key)|
                OperatorPublicKey { block_hash: hash.0, block_height, key: key.0 })
            .collect());

        let previous_masternode_entry_hashes_count = self.previous_masternode_entry_hashes.len();
        let previous_masternode_entry_hashes = boxed_vec(self.previous_masternode_entry_hashes
            .iter()
            .map(|(&BlockData { hash: block_hash, height: block_height}, &hash)|
                MasternodeEntryHash { block_hash: block_hash.0, block_height, hash: hash.0 })
            .collect());

        let previous_validity_count = self.previous_validity.len();
        let validity_vec: Vec<Validity> = Vec::with_capacity(previous_validity_count);
        let previous_validity = boxed_vec(self.previous_validity
            .iter()
            .map(|(&BlockData { hash, height: block_height}, &is_valid)|
                Validity { block_hash: hash.0, block_height, is_valid })
            .collect());

        let provider_registration_transaction_hash = boxed(self.provider_registration_transaction_hash.0);
        let SocketAddress { ip_address: ip, port } = self.socket_address;
        let ip_address = boxed(ip.0);
        let update_height= self.update_height;
        wrapped_types::MasternodeEntry {
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
}

impl<'a> ToFFI<'a> for quorum_entry::QuorumEntry<'a> {
    type Item = wrapped_types::QuorumEntry;

    fn encode(&self) -> Self::Item {
        let commitment_hash = if self.commitment_hash.is_none() {
            null_mut()
        } else {
            boxed(self.commitment_hash.unwrap().0)
        };
        let all_commitment_aggregated_signature = boxed(self.all_commitment_aggregated_signature.0);
        let quorum_entry_hash = boxed(self.quorum_entry_hash.0);
        let quorum_hash = boxed(self.quorum_hash.0);
        let quorum_public_key = boxed(self.quorum_public_key.0);
        let quorum_threshold_signature = boxed(self.quorum_threshold_signature.0);
        let quorum_verification_vector_hash = boxed(self.quorum_verification_vector_hash.0);
        let signers_bitset = boxed_vec(self.signers_bitset.to_vec());
        let signers_bitset_length = self.signers_bitset.len();
        let valid_members_bitset = boxed_vec(self.valid_members_bitset.to_vec());
        let valid_members_bitset_length = self.valid_members_bitset.len();
        wrapped_types::QuorumEntry {
            all_commitment_aggregated_signature,
            commitment_hash,
            length: self.length,
            llmq_type: self.llmq_type,
            quorum_entry_hash,
            quorum_hash,
            quorum_index: if self.quorum_index.is_none() { 0 } else { self.quorum_index.unwrap() },
            quorum_public_key,
            quorum_threshold_signature,
            quorum_verification_vector_hash,
            saved: self.saved,
            signers_bitset,
            signers_bitset_length,
            signers_count: self.signers_count.0,
            valid_members_bitset,
            valid_members_bitset_length,
            valid_members_count: self.valid_members_count.0,
            verified: self.verified,
            version: self.version,
        }
    }
}

impl<'a> ToFFI<'a> for mn_list_diff::MNListDiff<'a> {
    type Item = wrapped_types::MNListDiff;

    fn encode(&self) -> Self::Item {
        let base_block_hash = boxed(self.base_block_hash.0);
        let block_hash = boxed(self.block_hash.0);
        let total_transactions = self.total_transactions;
        let merkle_hashes = boxed_vec(self.merkle_hashes.to_vec());
        let merkle_hashes_count = self.merkle_hashes.len();
        let merkle_flags = boxed_vec(self.merkle_flags.to_vec());
        let merkle_flags_count = self.merkle_flags.len();
        let coinbase_transaction = boxed(self.coinbase_transaction.encode());
        let deleted_masternode_hashes_count = self.deleted_masternode_hashes.len();
        let deleted_masternode_hashes_vec: Vec<*mut [u8; 32]> = (0..deleted_masternode_hashes_count)
            .into_iter()
            .map(|i| boxed(self.deleted_masternode_hashes[i].0))
            .collect();
        let deleted_masternode_hashes = boxed_vec(deleted_masternode_hashes_vec);
        let mut deleted_quorums_vec: Vec<*mut LLMQTypedHash> = Vec::new();
        self.deleted_quorums.clone().into_iter().for_each(|(llmq_type, hashes)| {
            hashes.iter().for_each(|&hash| {
                let llmq_hash = boxed(hash.0);
                let llmq_type = llmq_type.into();
                deleted_quorums_vec.push(boxed(LLMQTypedHash { llmq_hash, llmq_type }));
            });
        });
        let deleted_quorums_count = deleted_quorums_vec.len();
        let deleted_quorums = boxed_vec(deleted_quorums_vec);
        let added_or_modified_masternodes_count = self.added_or_modified_masternodes.len();
        let added_or_modified_masternodes = encode_masternodes_map(&self.added_or_modified_masternodes);
        let mut added_quorums_vec: Vec<*mut wrapped_types::QuorumEntry> = Vec::new();
        self.added_quorums.clone().into_iter().for_each(|(llmq_type, map)| {
            map.iter().for_each(|(&hash, &entry)| {
                added_quorums_vec.push(boxed(entry.encode()));
            });
        });
        let added_quorums_count = added_quorums_vec.len();
        let added_quorums = boxed_vec(added_quorums_vec);
        Self::Item {
            base_block_hash,
            block_hash,
            total_transactions,
            merkle_hashes,
            merkle_hashes_count,
            merkle_flags,
            merkle_flags_count,
            coinbase_transaction,
            deleted_masternode_hashes_count,
            deleted_masternode_hashes,
            added_or_modified_masternodes_count,
            added_or_modified_masternodes,
            deleted_quorums_count,
            deleted_quorums,
            added_quorums_count,
            added_quorums,
            length: self.length,
            block_height: self.block_height
        }
    }
}
impl<'a> ToFFI<'a> for quorum_snapshot::QuorumSnapshot<'a> {
    type Item = wrapped_types::QuorumSnapshot;

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

impl<'a> ToFFI<'a> for quorum_rotation_info::QuorumRotationInfo<'a> {
    type Item = wrapped_types::QuorumRotationInfo;

    fn encode(&self) -> Self::Item {
        let snapshot_at_h_c = boxed(self.snapshot_at_h_c.encode());
        let snapshot_at_h_2c = boxed(self.snapshot_at_h_2c.encode());
        let snapshot_at_h_3c = boxed(self.snapshot_at_h_3c.encode());
        let list_diff_tip = boxed(self.list_diff_tip.encode());
        let list_diff_at_h = boxed(self.list_diff_at_h.encode());
        let list_diff_at_h_c = boxed(self.list_diff_at_h_c.encode());
        let list_diff_at_h_2c = boxed(self.list_diff_at_h_2c.encode());
        let list_diff_at_h_3c = boxed(self.list_diff_at_h_3c.encode());
        let extra_share = self.extra_share;
        let (snapshot_at_h_4c, list_diff_at_h_4c) = if extra_share {
            (boxed(self.snapshot_at_h_4c.as_ref().unwrap().encode()),
             boxed(self.list_diff_at_h_4c.as_ref().unwrap().encode()))
        } else {
            (null_mut(), null_mut())
        };
        let block_hash_list_num = self.block_hash_list.len();
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
                .collect());
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
            block_hash_list_num: block_hash_list_num as u32,
            block_hash_list,
            snapshot_list_num: snapshot_list_num as u32,
            snapshot_list,
            mn_list_diff_list_num: mn_list_diff_list_num as u32,
            mn_list_diff_list
        }
    }
}

pub fn encode_quorums_map(quorums: &HashMap<LLMQType, HashMap<UInt256, quorum_entry::QuorumEntry>>) -> *mut *mut LLMQMap {
    boxed_vec(quorums
        .iter()
        .map(|(&llmq_type, map)|
            boxed(LLMQMap {
                llmq_type: llmq_type.into(),
                values: boxed_vec((*map)
                    .iter()
                    .map(|(_, &entry)| boxed(entry.encode()))
                    .collect()),
                count: (*map).len()
            }))
        .collect())
}

pub fn encode_masternodes_map(masternodes: &BTreeMap<UInt256, masternode_entry::MasternodeEntry>) -> *mut *mut wrapped_types::MasternodeEntry {
    boxed_vec(masternodes
        .iter()
        .map(|(_, entry)| boxed((*entry).encode()))
        .collect())
}
