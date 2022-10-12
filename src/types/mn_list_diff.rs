use crate::ffi::boxer::{boxed, boxed_vec};
use crate::types::coinbase_transaction::CoinbaseTransaction;
use crate::types::llmq_entry::LLMQEntry;
use crate::types::masternode_entry::MasternodeEntry;
use crate::types::LLMQTypedHash;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dash_spv_models::common::llmq_type::LLMQType;
use dash_spv_primitives::crypto::var_array::VarArray;
use dash_spv_primitives::crypto::{UInt256, VarBytes};
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MNListDiff {
    pub base_block_hash: *mut [u8; 32],
    pub block_hash: *mut [u8; 32],
    pub total_transactions: u32,

    pub merkle_hashes: *mut *mut [u8; 32],
    pub merkle_hashes_count: usize,

    pub merkle_flags: *mut u8,
    pub merkle_flags_count: usize,

    pub coinbase_transaction: *mut CoinbaseTransaction,

    pub deleted_masternode_hashes_count: usize,
    pub deleted_masternode_hashes: *mut *mut [u8; 32],

    pub added_or_modified_masternodes_count: usize,
    pub added_or_modified_masternodes: *mut *mut MasternodeEntry,

    pub deleted_quorums_count: usize,
    pub deleted_quorums: *mut *mut LLMQTypedHash,

    pub added_quorums_count: usize,
    pub added_quorums: *mut *mut LLMQEntry,

    pub block_height: u32,
}

impl<'a> TryRead<'a, Endian> for MNListDiff {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let base_block_hash = boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
        let block_hash = boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
        let total_transactions = bytes.read_with::<u32>(offset, LE)?;
        let merkle_hashes = bytes.read_with::<VarArray<UInt256>>(offset, LE)?;
        let merkle_hashes_vec = boxed_vec(merkle_hashes.1.iter().map(|h| boxed(h.0)).collect());
        let merkle_flags_bytes = bytes.read_with::<VarBytes>(offset, LE)?;
        let coinbase_transaction = bytes.read_with::<CoinbaseTransaction>(offset, LE)?;
        let deleted_masternode_hashes_count = bytes
            .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
            .0 as usize;
        let mut deleted_masternode_hashes_vec: Vec<*mut [u8; 32]> =
            Vec::with_capacity(deleted_masternode_hashes_count as usize);
        for _i in 0..deleted_masternode_hashes_count {
            deleted_masternode_hashes_vec.push(boxed(bytes.read_with::<UInt256>(offset, LE)?.0));
        }
        let deleted_masternode_hashes = boxed_vec(deleted_masternode_hashes_vec);
        let added_or_modified_masternodes_count = bytes
            .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
            .0 as usize;
        let mut added_or_modified_masternodes_vec: Vec<*mut MasternodeEntry> =
            Vec::with_capacity(added_or_modified_masternodes_count);
        for _i in 0..added_or_modified_masternodes_count {
            added_or_modified_masternodes_vec
                .push(boxed(bytes.read_with::<MasternodeEntry>(offset, LE)?));
        }
        let added_or_modified_masternodes = boxed_vec(added_or_modified_masternodes_vec);
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let (deleted_quorums, deleted_quorums_count, added_quorums, added_quorums_count) =
            if quorums_active {
                let deleted_count = bytes
                    .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
                    .0 as usize;
                let mut deleted_vec: Vec<*mut LLMQTypedHash> = Vec::with_capacity(deleted_count);
                for _i in 0..deleted_count {
                    let llmq_type = bytes.read_with::<LLMQType>(offset, LE)?.into();
                    let llmq_hash = boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
                    deleted_vec.push(boxed(LLMQTypedHash {
                        llmq_type,
                        llmq_hash,
                    }));
                }
                let added_count = bytes
                    .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
                    .0 as usize;
                let mut added_vec: Vec<*mut LLMQEntry> = Vec::with_capacity(added_count);
                for _i in 0..added_count {
                    added_vec.push(boxed(bytes.read_with::<LLMQEntry>(offset, LE)?));
                }
                (
                    boxed_vec(deleted_vec),
                    deleted_count,
                    boxed_vec(added_vec),
                    added_count,
                )
            } else {
                (null_mut(), 0, null_mut(), 0)
            };
        Ok((
            Self {
                base_block_hash,
                block_hash,
                total_transactions,
                merkle_hashes: merkle_hashes_vec,
                merkle_hashes_count: merkle_hashes.1.len(),
                merkle_flags: boxed_vec(merkle_flags_bytes.1.to_vec()),
                merkle_flags_count: merkle_flags_bytes.0 .0 as usize,
                coinbase_transaction: boxed(coinbase_transaction),
                deleted_masternode_hashes_count,
                deleted_masternode_hashes,
                added_or_modified_masternodes_count,
                added_or_modified_masternodes,
                deleted_quorums_count,
                deleted_quorums,
                added_quorums_count,
                added_quorums,
                block_height: 0,
            },
            *offset,
        ))
    }
}

// impl MNListDiff {
//     pub fn from_data(
//         base_block_hash: UInt256,
//         block_hash: UInt256,
//         total_transactions: u32,
//         merkle_hashes: Vec<u8>,
//         merkle_flags: Vec<u8>,
//         coinbase_transaction: types::CoinbaseTransaction,
//         deleted_masternode_hashes: Vec<UInt256>
//     ) -> Self {
//         Self {
//             base_block_hash: boxed(base_block_hash.0),
//             block_hash: boxed(block_hash.0),
//             total_transactions: total_transactions,
//             merkle_hashes: boxed_vec(merkle_hashes),
//             merkle_hashes_count: merkle_hashes.len(),
//             merkle_flags: boxed_vec(merkle_flags),
//             merkle_flags_count: merkle_flags.len(),
//             coinbase_transaction: boxed(coinbase_transaction),
//             deleted_masternode_hashes_count,
//             deleted_masternode_hashes,
//             added_or_modified_masternodes_count,
//             added_or_modified_masternodes,
//             deleted_quorums_count,
//             deleted_quorums,
//             added_quorums_count,
//             added_quorums,
//             length: *offset,
//             block_height: 0
//         }
//     }
// }
