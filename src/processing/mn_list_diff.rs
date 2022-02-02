use std::collections::{BTreeMap, HashMap};
use byte::BytesExt;
use byte::ctx::Bytes;
use crate::{CoinbaseTransaction, LLMQType, MasternodeEntry, LLMQEntry, Reversable, UInt256, VarInt};
use crate::crypto::byte_util::{BytesDecodable, VarBytes};

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

    pub deleted_quorums: Vec<UInt256>,
    pub added_quorums: HashMap<UInt256, LLMQEntry<'a>>,

    pub length: usize,
    pub block_height: u32,
}


impl<'a> MNListDiff<'a> {
    pub fn new<F: Fn(UInt256) -> u32>(message: &'a [u8], offset: &mut usize, block_height_lookup: F) -> Option<Self> {
        let base_block_hash = UInt256::from_bytes(message, offset)?;
        let block_hash = UInt256::from_bytes(message, offset)?;
        let block_height= block_height_lookup(block_hash);
        let total_transactions = u32::from_bytes(message, offset)?;
        let merkle_hashes_count = 32 * VarInt::from_bytes(message, offset)?.0 as usize;
        let merkle_hashes = match message.read_with(offset, Bytes::Len(merkle_hashes_count)) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let merkle_flags_var_bytes = VarBytes::from_bytes(message, offset)?;
        let coinbase_transaction = CoinbaseTransaction::from_bytes(message, offset)?;
        let deleted_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let mut deleted_masternode_hashes: Vec<UInt256> = Vec::with_capacity(deleted_masternode_count as usize);
        for _i in 0..deleted_masternode_count {
            deleted_masternode_hashes.push(UInt256::from_bytes(message, offset)?);
        }
        let added_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = (0..added_masternode_count)
            .into_iter()
            .filter_map(|_i| {
                // assert_eq!(message.len(), MN_ENTRY_PAYLOAD_LENGTH);
                let mut entry = MasternodeEntry::from_bytes(message, offset)?;
                entry.update_with_block_height(block_height);
                Some(entry)
            })
            .fold(BTreeMap::new(),|mut acc, entry| {
                let hash = entry.provider_registration_transaction_hash.clone().reversed();
                acc.insert(hash, entry);
                acc
            });

        let mut deleted_quorums: Vec<UInt256> = Vec::new();
        let mut added_quorums: HashMap<UInt256, LLMQEntry> = HashMap::new();
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        if quorums_active {
            let deleted_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..deleted_quorums_count {
                let _llmq_type = LLMQType::from_bytes(message, offset)?;
                let llmq_hash = UInt256::from_bytes(message, offset)?;
                deleted_quorums.push(llmq_hash);
                // deleted_quorums
                //     .entry(llmq_type)
                //     .or_insert(Vec::new())
                //     .push(llmq_hash);
            }
            let added_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..added_quorums_count {
                if let Some(entry) = LLMQEntry::from_bytes(message, offset) {
                    added_quorums.insert(entry.llmq_hash, entry);
                }
            }
        }
        Some(Self {
            base_block_hash,
            block_hash,
            total_transactions,
            merkle_hashes,
            merkle_hashes_count,
            merkle_flags: merkle_flags_var_bytes.1,
            merkle_flags_count: merkle_flags_var_bytes.0.0 as usize,
            coinbase_transaction,
            deleted_masternode_hashes,
            added_or_modified_masternodes,
            deleted_quorums,
            added_quorums,
            length: *offset,
            block_height
        })
    }
}
