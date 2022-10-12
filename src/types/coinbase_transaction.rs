use crate::ffi::boxer::boxed;
use crate::types::transaction::Transaction;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dash_spv_primitives::crypto::byte_util::UInt256;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CoinbaseTransaction {
    pub base: *mut Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: *mut [u8; 32],
    pub merkle_root_llmq_list: *mut [u8; 32],
}
impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let base = boxed(bytes.read_with::<Transaction>(offset, LE)?);
        let _extra_payload_size_var_int =
            bytes.read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(offset, LE)?;
        let height = bytes.read_with::<u32>(offset, LE)?;
        let merkle_root_mn_list = boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
        let merkle_root_llmq_list = if coinbase_transaction_version >= 2 {
            boxed(bytes.read_with::<UInt256>(offset, LE)?.0)
        } else {
            null_mut()
        };
        Ok((
            Self {
                base,
                coinbase_transaction_version,
                height,
                merkle_root_mn_list,
                merkle_root_llmq_list,
            },
            *offset,
        ))
    }
}
