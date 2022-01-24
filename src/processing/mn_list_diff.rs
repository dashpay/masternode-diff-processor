use std::collections::{BTreeMap, HashMap};
use byte::{BytesExt, LE};
use crate::{CoinbaseTransaction, LLMQType, MasternodeEntry, MNPayload, QuorumEntry, Reversable, UInt256, VarInt};
use crate::consensus::Decodable;

#[derive(Debug)]
pub struct MNListDiff<'a> {
    pub base_block_hash: UInt256,
    pub block_hash: UInt256,
    pub total_transactions: u32,
    pub merkle_hashes: &'a [u8],
    pub merkle_hashes_count: usize,

    pub merkle_flags: &'a [u8],
    pub merkle_flags_count: usize,
    pub coinbase_transaction: CoinbaseTransaction<'a>,

    pub deleted_masternode_hashes: Vec<UInt256>,
    pub added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry>,

    pub deleted_quorums: HashMap<LLMQType, Vec<UInt256>>,
    pub added_quorums: HashMap<LLMQType, HashMap<UInt256, QuorumEntry<'a>>>,

    pub length: usize,
    pub block_height: u32,
}


impl<'a> MNListDiff<'a> {
    pub fn new<F: Fn(UInt256) -> u32>(message: &'a [u8], message_length: usize, block_height_lookup: F) -> Option<Self> {
        let offset = &mut 0;
        let base_block_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let block_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let block_height= block_height_lookup(block_hash);
        let total_transactions = match message.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let merkle_hash_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += merkle_hash_var_int.len();
        let merkle_hashes_count = (merkle_hash_var_int.0 as usize) * 32;
        let merkle_hashes = &message[*offset..*offset + merkle_hashes_count];
        *offset += merkle_hashes_count;
        let merkle_flag_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += merkle_flag_var_int.len();

        let merkle_flags_count = merkle_flag_var_int.0 as usize;
        let merkle_flags = &message[*offset..*offset + merkle_flags_count];
        *offset += merkle_flags_count;
        let coinbase_transaction = CoinbaseTransaction::new(&message[*offset..]);
        if coinbase_transaction.is_none() { return None; }
        let coinbase_transaction = coinbase_transaction.unwrap();
        *offset += coinbase_transaction.base.payload_offset;
        if message_length - *offset < 1 { return None; }
        let deleted_masternode_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += deleted_masternode_var_int.len();
        let deleted_masternode_count = deleted_masternode_var_int.0.clone();
        let mut deleted_masternode_hashes: Vec<UInt256> = Vec::with_capacity(deleted_masternode_count as usize);
        for _i in 0..deleted_masternode_count {
            deleted_masternode_hashes.push(match message.read_with::<UInt256>(offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            });
        }
        let added_masternode_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        *offset += added_masternode_var_int.len();
        let added_masternode_count = added_masternode_var_int.0.clone();
        let added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = (0..added_masternode_count)
            .into_iter()
            .map(|_i| message.read_with::<MNPayload>(offset, LE))
            .filter(|payload| payload.is_ok())
            .map(|payload| MasternodeEntry::new(payload.unwrap(), block_height))
            .filter(|entry| entry.is_some())
            .fold(BTreeMap::new(),|mut acc, entry| {
                let mn_entry = entry.unwrap();
                let hash = mn_entry.provider_registration_transaction_hash.clone().reversed();
                acc.insert(hash, mn_entry);
                acc
            });

        let mut deleted_quorums: HashMap<LLMQType, Vec<UInt256>> = HashMap::new();
        let mut added_quorums: HashMap<LLMQType, HashMap<UInt256, QuorumEntry>> = HashMap::new();

        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;

        if quorums_active {
            // deleted quorums
            if message_length - *offset < 1 { return None; }
            let deleted_quorums_var_int = match VarInt::consensus_decode(&message[*offset..]) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            *offset += deleted_quorums_var_int.len();
            let deleted_quorums_count = deleted_quorums_var_int.0.clone();
            for _i in 0..deleted_quorums_count {
                let llmq_type = match message.read_with::<LLMQType>(offset, LE) {
                    Ok(data) => data,
                    Err(_err) => { return None; }
                };
                let llmq_hash = match message.read_with::<UInt256>(offset, LE) {
                    Ok(data) => data,
                    Err(_err) => { return None; }
                };
                if deleted_quorums.contains_key(&llmq_type) {
                    deleted_quorums.get_mut(&llmq_type).unwrap().push(llmq_hash);
                } else {
                    deleted_quorums.insert(llmq_type, vec![llmq_hash]);
                }
            }

            // added quorums
            if message_length - *offset < 1 { return None; }
            let added_quorums_var_int = match VarInt::consensus_decode(&message[*offset..]) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            *offset += added_quorums_var_int.len();
            let added_quorums_count = added_quorums_var_int.0.clone();
            for _i in 0..added_quorums_count {
                if let Some(quorum_entry) = QuorumEntry::new(message, *offset) {
                    *offset += quorum_entry.length;
                    let quorum_hash = quorum_entry.quorum_hash;
                    let llmq_type = quorum_entry.llmq_type;
                    added_quorums
                        .entry(llmq_type)
                        .or_insert(HashMap::new())
                        .insert(quorum_hash, quorum_entry);
                }
            }
        }
        let length = *offset;
        Some(Self {
            base_block_hash,
            block_hash,
            total_transactions,
            merkle_hashes,
            merkle_hashes_count,
            merkle_flags,
            merkle_flags_count,
            coinbase_transaction,
            deleted_masternode_hashes,
            added_or_modified_masternodes,
            deleted_quorums,
            added_quorums,
            length,
            block_height
        })
    }
}
