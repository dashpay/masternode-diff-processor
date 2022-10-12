use crate::tx::Transaction;
use crate::tx::TransactionType::Coinbase;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::consensus::Encodable;
use dash_spv_primitives::crypto::UInt256;
use dash_spv_primitives::hashes::{sha256d, Hash};

#[derive(Debug, Clone)]
pub struct CoinbaseTransaction {
    pub base: Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: UInt256,
    pub merkle_root_llmq_list: Option<UInt256>,
}

impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let mut base = bytes.read_with::<Transaction>(offset, endian)?;
        let _extra_payload_size = bytes.read_with::<VarInt>(offset, endian)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(offset, endian)?;
        let height = bytes.read_with::<u32>(offset, endian)?;
        let merkle_root_mn_list = bytes.read_with::<UInt256>(offset, endian)?;
        let merkle_root_llmq_list = if coinbase_transaction_version >= 2 {
            let root = bytes.read_with::<UInt256>(offset, endian)?;
            Some(root)
        } else {
            None
        };
        base.tx_type = Coinbase;
        base.payload_offset = *offset;
        let mut tx = Self {
            base,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list,
        };
        tx.base.tx_hash = Some(UInt256(sha256d::Hash::hash(&tx.to_data()).into_inner()));
        Ok((tx, *offset))
    }
}

impl CoinbaseTransaction {
    fn payload_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        *offset += self
            .coinbase_transaction_version
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += self.height.consensus_encode(&mut buffer).unwrap();
        *offset += self
            .merkle_root_mn_list
            .consensus_encode(&mut buffer)
            .unwrap();
        if self.coinbase_transaction_version >= 2 {
            if let Some(llmq_list) = self.merkle_root_llmq_list {
                *offset += llmq_list.consensus_encode(&mut buffer).unwrap();
            }
        }
        buffer
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.to_data_with_subscript_index(u64::MAX)
    }

    pub fn to_data_with_subscript_index(&self, subscript_index: u64) -> Vec<u8> {
        let mut buffer = Transaction::data_with_subscript_index_static(
            subscript_index,
            self.base.version,
            self.base.tx_type,
            &self.base.inputs,
            &self.base.outputs,
            self.base.lock_time,
        );
        let offset: &mut usize = &mut 0;
        let payload = self.payload_data();
        *offset += payload.consensus_encode(&mut buffer).unwrap();
        buffer
    }

    pub fn has_found_coinbase(&mut self, hashes: &Vec<UInt256>) -> bool {
        if let Some(coinbase_hash) = self.base.tx_hash {
            self.has_found_coinbase_internal(coinbase_hash, hashes)
        } else {
            let coinbase_hash = UInt256(sha256d::Hash::hash(&self.to_data()).into_inner());
            self.base.tx_hash = Some(coinbase_hash);
            self.has_found_coinbase_internal(coinbase_hash, hashes)
        }
    }

    fn has_found_coinbase_internal(&self, coinbase_hash: UInt256, hashes: &Vec<UInt256>) -> bool {
        hashes
            .iter()
            .filter(|&h| coinbase_hash.cmp(h).is_eq())
            .count()
            > 0
    }
}
