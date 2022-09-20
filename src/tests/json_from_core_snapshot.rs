use std::collections::BTreeMap;
use std::num::ParseIntError;
use byte::BytesExt;
use byte::ctx::Bytes;
use dash_spv_models::common::{LLMQSnapshotSkipMode, LLMQType, SocketAddress};
use dash_spv_models::{llmq, masternode};
use dash_spv_models::llmq::MNListDiff;
use dash_spv_models::tx::CoinbaseTransaction;
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::{UInt160, UInt256, UInt384, UInt768, VarBytes};
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, Reversable};
use dash_spv_primitives::crypto::var_array::VarArray;
use dash_spv_primitives::hashes::hex::FromHex;
use dash_spv_primitives::util::base58;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Masternode {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: String,
    pub address: String,
    pub payee: String,
    pub status: String,
    pub pospenaltyscore: i64,
    pub lastpaidtime: i64,
    pub lastpaidblock: i64,
    pub owneraddress: String,
    pub votingaddress: String,
    pub collateraladdress: String,
    pub pubkeyoperator: String,
}

#[derive(Serialize, Deserialize)]
pub struct QRInfo {
    #[serde(rename = "extraShare")]
    pub extra_share: bool,
    #[serde(rename = "quorumSnapshotAtHMinusC")]
    pub quorum_snapshot_at_hminus_c: Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus2C")]
    pub quorum_snapshot_at_hminus2c: Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus3C")]
    pub quorum_snapshot_at_hminus3c: Snapshot,
    #[serde(rename = "mnListDiffTip")]
    pub mn_list_diff_tip: ListDiff,
    #[serde(rename = "mnListDiffH")]
    pub mn_list_diff_h: ListDiff,
    #[serde(rename = "mnListDiffAtHMinusC")]
    pub mn_list_diff_at_hminus_c: ListDiff,
    #[serde(rename = "mnListDiffAtHMinus2C")]
    pub mn_list_diff_at_hminus2c: ListDiff,
    #[serde(rename = "mnListDiffAtHMinus3C")]
    pub mn_list_diff_at_hminus3c: ListDiff,
    #[serde(rename = "lastCommitmentPerIndex")]
    pub last_commitment_per_index: Vec<LLMQ>,
    #[serde(rename = "quorumSnapshotList")]
    pub quorum_snapshot_list: Vec<Snapshot>,
    #[serde(rename = "mnListDiffList")]
    pub mn_list_diff_list: Vec<ListDiff>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "activeQuorumMembers")]
    pub active_quorum_members: Vec<bool>,
    #[serde(rename = "mnSkipListMode")]
    pub mn_skip_list_mode: i64,
    #[serde(rename = "mnSkipList")]
    pub mn_skip_list: Vec<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct LLMQ {
    pub version: i64,
    #[serde(rename = "llmqType")]
    pub llmq_type: i64,
    #[serde(rename = "quorumHash")]
    pub quorum_hash: String,
    #[serde(rename = "quorumIndex")]
    pub quorum_index: i64,
    #[serde(rename = "signersCount")]
    pub signers_count: i64,
    pub signers: String,
    #[serde(rename = "validMembersCount")]
    pub valid_members_count: i64,
    #[serde(rename = "validMembers")]
    pub valid_members: String,
    #[serde(rename = "quorumPublicKey")]
    pub quorum_public_key: String,
    #[serde(rename = "quorumVvecHash")]
    pub quorum_vvec_hash: String,
    #[serde(rename = "quorumSig")]
    pub quorum_sig: String,
    #[serde(rename = "membersSig")]
    pub members_sig: String,
}

#[derive(Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "proRegTxHash")]
    pub pro_reg_tx_hash: String,
    #[serde(rename = "confirmedHash")]
    pub confirmed_hash: String,
    pub service: String,
    #[serde(rename = "pubKeyOperator")]
    pub pub_key_operator: String,
    #[serde(rename = "votingAddress")]
    pub voting_address: String,
    #[serde(rename = "isValid")]
    pub is_valid: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ListDiff {
    #[serde(rename = "baseBlockHash")]
    pub base_block_hash: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "cbTxMerkleTree")]
    pub cb_tx_merkle_tree: String,
    #[serde(rename = "cbTx")]
    pub cb_tx: String,
    #[serde(rename = "deletedMNs")]
    pub deleted_mns: Vec<String>,
    #[serde(rename = "mnList")]
    pub mn_list: Vec<Node>,
    #[serde(rename = "deletedQuorums")]
    pub deleted_quorums: Vec<String>,
    #[serde(rename = "newQuorums")]
    pub new_quorums: Vec<LLMQ>,
    #[serde(rename = "merkleRootMNList")]
    pub merkle_root_mnlist: String,
    #[serde(rename = "merkleRootQuorums")]
    pub merkle_root_quorums: String,
}

pub fn block_hash_to_block_hash(block_hash: String) -> UInt256 {
    UInt256::from_hex(block_hash.as_str()).unwrap()
}

pub fn snapshot_to_snapshot(snapshot: Snapshot) -> llmq::LLMQSnapshot {
    let member_list = bools_to_bytes(snapshot.active_quorum_members);
    let skip_list = snapshot.mn_skip_list;
    let skip_list_mode = LLMQSnapshotSkipMode::from(snapshot.mn_skip_list_mode as u32);
    llmq::LLMQSnapshot::new(member_list, skip_list, skip_list_mode)
}

pub fn value_to_snapshot(value: &serde_json::Value) -> llmq::LLMQSnapshot {
    let snapshot: Snapshot = serde_json::from_value(value.clone()).unwrap();
    let member_list = bools_to_bytes(snapshot.active_quorum_members);
    let skip_list = snapshot.mn_skip_list;
    let skip_list_mode = LLMQSnapshotSkipMode::from(snapshot.mn_skip_list_mode as u32);
    llmq::LLMQSnapshot::new(member_list, skip_list, skip_list_mode)
}


pub fn quorums_to_quorums(value: Vec<LLMQ>) -> BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>> {
    let mut quorums: BTreeMap<LLMQType, BTreeMap<UInt256, masternode::LLMQEntry>> = BTreeMap::new();
    value.into_iter().filter(|llmq| LLMQType::from(llmq.llmq_type as u8) == LLMQType::Llmqtype60_75).for_each(|llmq| {
        let entry = masternode::LLMQEntry::new(
            llmq.version as u16,
            LLMQType::from(llmq.llmq_type as u8),
            block_hash_to_block_hash(llmq.quorum_hash),
            Some(llmq.quorum_index as u16),
            VarInt(llmq.signers_count as u64),
            VarInt(llmq.valid_members_count as u64),
            llmq.signers.as_bytes().to_vec(),
            llmq.valid_members.as_bytes().to_vec(),
            UInt384::from_hex(llmq.quorum_public_key.as_str()).unwrap(),
            UInt256::from_hex(llmq.quorum_vvec_hash.as_str()).unwrap(),
            UInt768::from_hex(llmq.quorum_sig.as_str()).unwrap(),
            UInt768::from_hex(llmq.members_sig.as_str()).unwrap()
        );
        quorums
            .entry(entry.llmq_type)
            .or_insert(BTreeMap::new())
            .insert(entry.llmq_hash, entry);

    });
    quorums
}

// pub fn masternodes_to_masternodes(value: Vec<Masternode>) -> BTreeMap<UInt256, masternode::MasternodeEntry> {
//     let map: BTreeMap<UInt256, masternode::MasternodeEntry> = value
//         .into_iter()
//         .filter_map(|node| {
//
//
//             // #[serde(rename = "proTxHash")]
//             // pub pro_tx_hash: String,
//             // pub address: String,
//             // pub payee: String,
//             // pub status: String,
//             // pub pospenaltyscore: i64,
//             // pub lastpaidtime: i64,
//             // pub lastpaidblock: i64,
//             // pub owneraddress: String,
//             // pub votingaddress: String,
//             // pub collateraladdress: String,
//             // pub pubkeyoperator: String,
//
//
//             let provider_registration_transaction_hash = UInt256::from_hex(node.pro_tx_hash.as_str()).unwrap();
//             let confirmed_hash = UInt256::from_hex(node.confirmed_hash.as_str()).unwrap();
//             // node.service don't really need
//             let socket_address = SocketAddress { ip_address: Default::default(), port: 0 };
//             let voting_bytes = base58::from(node.votingaddress.as_str()).unwrap();
//             let key_id_voting = UInt160::from_bytes(&voting_bytes, &mut 0).unwrap();
//             let operator_public_key = UInt384::from_hex(node.pubkeyoperator.as_str()).unwrap();
//             let is_valid = node.status == "ENABLED";
//             let entry = masternode::MasternodeEntry::new(provider_registration_transaction_hash, confirmed_hash, socket_address, key_id_voting, operator_public_key, if is_valid { 1 } else { 0 });
//             // assert_eq!(message.len(), MN_ENTRY_PAYLOAD_LENGTH);
//             // entry.update_with_block_height(block_height);
//             Some(entry)
//         })
//         .fold(BTreeMap::new(), |mut acc, entry| {
//             let hash = entry
//                 .provider_registration_transaction_hash
//                 .clone()
//                 .reversed();
//             acc.insert(hash, entry);
//             acc
//         });
//     map
// }

pub fn nodes_to_masternodes(value: Vec<Node>) -> BTreeMap<UInt256, masternode::MasternodeEntry> {
    let map: BTreeMap<UInt256, masternode::MasternodeEntry> = value
        .into_iter()
        .filter_map(|node| {
            let provider_registration_transaction_hash = UInt256::from_hex(node.pro_reg_tx_hash.as_str()).unwrap();
            let confirmed_hash = UInt256::from_hex(node.confirmed_hash.as_str()).unwrap();
            // node.service don't really need
            let socket_address = SocketAddress { ip_address: Default::default(), port: 0 };
            let voting_bytes = base58::from(node.voting_address.as_str()).unwrap();
            let key_id_voting = UInt160::from_bytes(&voting_bytes, &mut 0).unwrap();
            let operator_public_key = UInt384::from_hex(node.pub_key_operator.as_str()).unwrap();
            let is_valid = node.is_valid;
            let entry = masternode::MasternodeEntry::new(provider_registration_transaction_hash, confirmed_hash, socket_address, key_id_voting, operator_public_key, if is_valid { 1 } else { 0 });
            // assert_eq!(message.len(), MN_ENTRY_PAYLOAD_LENGTH);
            // entry.update_with_block_height(block_height);
            Some(entry)
        })
        .fold(BTreeMap::new(), |mut acc, entry| {
            let hash = entry
                .provider_registration_transaction_hash
                .clone()
                .reversed();
            acc.insert(hash, entry);
            acc
        });
    map
}

pub fn parse_coinbase_tx_merkle_tree(bytes: &[u8]) -> (u32, VarArray<UInt256>, &[u8], usize) {
    let offset = &mut 0;
    let total_transactions = u32::from_bytes(bytes, offset).unwrap();
    let merkle_hashes = VarArray::<UInt256>::from_bytes(bytes, offset).unwrap();
    let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset).unwrap();
    (total_transactions, merkle_hashes, merkle_flags_var_bytes.1, merkle_flags_var_bytes.0.0 as usize)
}

pub fn bools_to_bytes(bools: Vec<bool>) -> Vec<u8> {
    let mut b = Vec::<u8>::with_capacity(bools.len() / 8);
    // let mut b = [0u8; bools.len() / 8];

    for (idx, bit) in bools.into_iter().enumerate() {
        let byte = idx / 8;
        let shift = 7 - idx % 8;
        if b.get(byte).is_none() {
            b.push((bit as u8) << shift);
        } else {
            b[byte] |= (bit as u8) << shift;
        }
    }
    b
}

pub fn decode_hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn vec_to_arr<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn masternode_list_from_genesis_diff<BHL: Fn(UInt256) -> u32 + Copy>(
    diff: ListDiff, block_height_lookup: BHL) -> MNListDiff {
    let base_block_hash = UInt256::from_hex(diff.base_block_hash.as_str()).unwrap().reversed();
    let block_hash = UInt256::from_hex(diff.block_hash.as_str()).unwrap().reversed();
    let cb_tx_bytes = Vec::from_hex(diff.cb_tx.as_str()).unwrap();
    let coinbase_transaction = CoinbaseTransaction::from_bytes(&cb_tx_bytes, &mut 0).unwrap();
    // let tree_bytes = diff.cb_tx_merkle_tree.as_bytes();
    let tree_bytes = Vec::from_hex(diff.cb_tx_merkle_tree.as_str()).unwrap();
    let tree_bytes = tree_bytes.as_slice();

    let offset = &mut 0;
    let total_transactions = u32::from_bytes(tree_bytes, offset).unwrap();
    let merkle_hashes = VarArray::<UInt256>::from_bytes(tree_bytes, offset).unwrap();
    let merkle_flags_var_int: VarInt = VarInt::from_bytes(tree_bytes, offset).unwrap();
    let merkle_flags_count = merkle_flags_var_int.0 as usize;
    let merkle_flags: &[u8] = tree_bytes.read_with(offset, Bytes::Len(merkle_flags_count)).unwrap();

    let deleted_masternode_hashes = diff.deleted_mns.iter().map(|s| UInt256::from_hex(s.as_str()).unwrap()).collect();
    let added_or_modified_masternodes = nodes_to_masternodes(diff.mn_list);
    // in that snapshot it's always empty
    let deleted_quorums = BTreeMap::default();
    let added_quorums = quorums_to_quorums(diff.new_quorums);
    println!("block_hash_tip: {}", block_hash);
    let mn_list_diff = MNListDiff {
        base_block_hash,
        block_hash,
        total_transactions,
        merkle_hashes,
        merkle_flags: merkle_flags.to_vec(),
        coinbase_transaction,
        deleted_masternode_hashes,
        added_or_modified_masternodes,
        deleted_quorums,
        added_quorums,
        block_height: block_height_lookup(block_hash.clone())
    };
    mn_list_diff
}
