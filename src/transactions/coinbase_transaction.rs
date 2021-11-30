use byte::{BytesExt, LE};
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::UInt256;
use crate::hashes::{Hash, sha256d};
use crate::transactions::transaction::Transaction;
use crate::transactions::transaction::TransactionType::Coinbase;

// #[repr(C)]
#[derive(Debug)]
pub struct CoinbaseTransaction<'a> {
    pub base: Transaction<'a>,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: UInt256,
    pub merkle_root_llmq_list: Option<UInt256>,
}

impl<'a> CoinbaseTransaction<'a> {
    pub fn new(message: &'a [u8]) -> Option<Self> {
        if let Some(mut base) = Transaction::new(message) {
            base.tx_type = Coinbase;
            let offset = &mut base.payload_offset;
            let extra_payload_size = match VarInt::consensus_decode(&message[*offset..]) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            *offset += extra_payload_size.len();
            let coinbase_transaction_version = match message.read_with::<u16>(offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let height = match message.read_with::<u32>(offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let merkle_root_mn_list = match message.read_with::<UInt256>(offset, LE) {
                Ok(data) => data,
                Err(_err) => { return None; }
            };
            let merkle_root_llmq_list: Option<UInt256> =
                if coinbase_transaction_version == 2 {
                    match message.read_with::<UInt256>(offset, LE) {
                        Ok(data) => Some(data),
                        Err(_err) => { return None; }
                    }
                } else { None };

            base.payload_offset = offset.clone();

            let mut tx = Self {
                base,
                coinbase_transaction_version,
                height,
                merkle_root_mn_list,
                merkle_root_llmq_list
            };
            tx.base.tx_hash = Some(UInt256(sha256d::Hash::hash(&tx.to_data()).into_inner()));
            return Some(tx);
        }
        None
    }

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
}
