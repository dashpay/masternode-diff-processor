use std::convert::TryInto;
use std::io::Write;
use byte::{BytesExt, LE};
use sha2::digest::DynDigest;
use uint::byteorder::ReadBytesExt;
use crate::consensus::encode::VarInt;
use crate::crypto::data_ops::sha256_2;
use crate::transactions::transaction::{ITransaction, Transaction};
use crate::transactions::transaction::TransactionType::{Classic, Coinbase};

#[repr(C)]
#[derive(Debug)]
pub struct CoinbaseTransaction<'a, T: ITransaction> {
    pub base: Transaction<'a, T>,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: [u8; 32],
    pub merkle_root_llmq_list: Option<[u8; 32]>,
}

impl<'a> CoinbaseTransaction<dyn ITransaction> {
    pub fn new(message: &[u8]) -> Option<CoinbaseTransaction<T>> {
        let mut base = Transaction::new(message);
        if base.is_none() { return None; }
        base?.tx_type = Coinbase;
        let length = message.len();
        let mut offset = base?.payload_offset;
        if length - offset < 1 { return None; }
        let extra_payload_size = VarInt(offset as u64);
        offset += extra_payload_size.len();
        if length - offset < 2 { return None; }
        let coinbase_transaction_version = message.read_with::<u16>(offset, LE)?;
        if length - offset < 4 { return None; }
        let height = message.read_with::<u32>(offset, LE)?;
        if length - offset < 32 { return None; }
        let merkle_root_mn_list = message.read_with::<[u8; 32]>(offset, LE)?;
        let mut merkle_root_llmq_list: Option<[u8; 32]> =
            if coinbase_transaction_version != 2 || length - offset < 32 {
                None
            } else {
                Some(message.read_with::<[u8; 32]>(offset, LE)?)
            };
        base?.payload_offset = offset;
        base?.tx_hash = Some(sha256_2(&base.data));
        Some(CoinbaseTransaction {
            base: base?,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list
        })
    }

    fn payload_data(&self) -> &[u8] {
        let mut buf = [0u8; 304..560];
        buf[0..15].copy_from_slice(&self.coinbase_transaction_version.to_be_bytes());
        buf[16..47].copy_from_slice(&self.height.to_be_bytes());
        buf[48..303].copy_from_slice(&self.merkle_root_mn_list);
        if self.coinbase_transaction_version >= 2 {
            if let llmq_list = self.merkle_root_llmq_list? {
                buf[304..559].copy_from_slice(&llmq_list);
            }
        }
        &buf
    }
}
