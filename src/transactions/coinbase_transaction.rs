use byte::{BytesExt, LE, TryRead};
use byte::ctx::Endian;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::UInt256;
use crate::hashes::{Hash, sha256d};
use crate::transactions::transaction::Transaction;
use crate::transactions::transaction::TransactionType::Coinbase;

#[derive(Debug)]
pub struct CoinbaseTransaction<'a> {
    pub base: Transaction<'a>,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: UInt256,
    pub merkle_root_llmq_list: Option<UInt256>,
}

impl<'a> TryRead<'a, Endian> for CoinbaseTransaction<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let mut base = bytes.read_with::<Transaction>(offset, endian)?;
        let extra_payload_size = bytes.read_with::<VarInt>(offset, endian)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(offset, endian)?;
        let height = bytes.read_with::<u32>(offset, endian)?;
        let merkle_root_mn_list = bytes.read_with::<UInt256>(offset, endian)?;
        let merkle_root_llmq_list =
            if coinbase_transaction_version >= 2 {
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
            merkle_root_llmq_list
        };
        tx.base.tx_hash = Some(UInt256(sha256d::Hash::hash(&tx.to_data()).into_inner()));
        Ok((tx, *offset))
    }
}

impl<'a> CoinbaseTransaction<'a> {

    fn payload_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        *offset += self.coinbase_transaction_version.consensus_encode(&mut buffer).unwrap();
        *offset += self.height.consensus_encode(&mut buffer).unwrap();
        *offset += self.merkle_root_mn_list.consensus_encode(&mut buffer).unwrap();
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
        let mut buffer = Transaction::data_with_subscript_index_static(subscript_index, self.base.version, self.base.tx_type, &self.base.inputs, &self.base.outputs, self.base.lock_time);
        let offset: &mut usize = &mut 0;
        let payload = self.payload_data();
        *offset += payload.consensus_encode(&mut buffer).unwrap();
        buffer
    }

    pub fn has_found_coinbase(&self, hashes: &[u8]) -> bool {
        if let Some(coinbase_hash) = self.base.tx_hash {
            let offset = &mut 0;
            for _i in 0..hashes.len() {
                if let Ok(h) = hashes.read_with::<UInt256>(offset, LE) {
                    println!("finding coinbase: {:?} == {:?}", coinbase_hash, h);
                    if h == coinbase_hash {
                        return true;
                    }
                }
            }
        }
        false
    }
}
