use crate::common::LLMQType;
use crate::masternode::{LLMQEntry, MasternodeEntry};
use crate::tx::CoinbaseTransaction;
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, Reversable};
use dash_spv_primitives::crypto::var_array::VarArray;
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::hex::ToHex;
use std::collections::BTreeMap;
use byte::BytesExt;

#[derive(Clone)]
pub struct MNListDiff {
    pub base_block_hash: UInt256,
    pub block_hash: UInt256,
    pub total_transactions: u32,
    pub merkle_hashes: VarArray<UInt256>,
    pub merkle_flags: Vec<u8>,
    // pub merkle_flags: &'a [u8],
    // pub merkle_flags_count: usize,
    pub coinbase_transaction: CoinbaseTransaction,
    pub deleted_masternode_hashes: Vec<UInt256>,
    pub added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry>,
    pub deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>>,
    pub added_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
    pub block_height: u32,
}

impl std::fmt::Debug for MNListDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MNListDiff")
            .field("base_block_hash", &self.base_block_hash)
            .field("block_hash", &self.block_hash)
            .field("total_transactions", &self.total_transactions)
            .field("merkle_hashes", &self.merkle_hashes)
            .field("merkle_flags", &self.merkle_flags.to_hex())
            .field("merkle_flags_count", &self.merkle_flags.len())
            .field("coinbase_transaction", &self.coinbase_transaction)
            .field("deleted_masternode_hashes", &self.deleted_masternode_hashes)
            .field(
                "added_or_modified_masternodes",
                &self.added_or_modified_masternodes,
            )
            .field("deleted_quorums", &self.deleted_quorums)
            .field("added_quorums", &self.added_quorums)
            .field("block_height", &self.block_height)
            .finish()
    }
}

impl MNListDiff {
    pub fn new<F: Fn(UInt256) -> u32>(
        message: &[u8],
        offset: &mut usize,
        block_height_lookup: F,
    ) -> Option<Self> {
        let base_block_hash = UInt256::from_bytes(message, offset)?;
        let block_hash = UInt256::from_bytes(message, offset)?;
        let block_height = block_height_lookup(block_hash);
        let total_transactions = u32::from_bytes(message, offset)?;
        let merkle_hashes = VarArray::<UInt256>::from_bytes(message, offset)?;
        let merkle_flags_count = VarInt::from_bytes(message, offset)?.0 as usize;
        let merkle_flags: &[u8] = match message.read_with(offset, byte::ctx::Bytes::Len(merkle_flags_count)) {
            Ok(data) => data,
            Err(_err) => { return None; },
        };
        let coinbase_transaction = CoinbaseTransaction::from_bytes(message, offset)?;
        let deleted_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let mut deleted_masternode_hashes: Vec<UInt256> =
            Vec::with_capacity(deleted_masternode_count as usize);
        for _i in 0..deleted_masternode_count {
            deleted_masternode_hashes.push(UInt256::from_bytes(message, offset)?);
        }
        let added_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = (0
            ..added_masternode_count)
            .into_iter()
            .filter_map(|_i| {
                // assert_eq!(message.len(), MN_ENTRY_PAYLOAD_LENGTH);
                let mut entry = MasternodeEntry::from_bytes(message, offset)?;
                entry.update_with_block_height(block_height);
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

        let mut deleted_quorums: BTreeMap<LLMQType, Vec<UInt256>> = BTreeMap::new();
        let mut added_quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = BTreeMap::new();
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        if quorums_active {
            let deleted_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..deleted_quorums_count {
                let llmq_type = LLMQType::from_bytes(message, offset)?;
                let llmq_hash = UInt256::from_bytes(message, offset)?;
                deleted_quorums
                    .entry(llmq_type)
                    .or_insert(Vec::new())
                    .push(llmq_hash);
            }
            let added_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..added_quorums_count {
                if let Some(entry) = LLMQEntry::from_bytes(message, offset) {
                    added_quorums
                        .entry(entry.llmq_type)
                        .or_insert(BTreeMap::new())
                        .insert(entry.llmq_hash, entry);
                }
            }
        }
        Some(Self {
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
            block_height,
        })
    }
}
