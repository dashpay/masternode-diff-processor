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
use crate::transactions::{coinbase_transaction, transaction};

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
