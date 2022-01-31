use std::ptr::null_mut;
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use crate::boxed_vec;
use crate::crypto::byte_util::data_at_offset_from;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct TransactionOutput {
    pub amount: u64,
    pub script: *mut u8,
    pub script_length: usize,
    pub address: *mut u8,
    pub address_length: usize,
}
impl<'a> TryRead<'a, Endian> for TransactionOutput {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let amount = bytes.read_with::<u64>(offset, LE)?;
        let (script, script_length) = match data_at_offset_from(bytes, offset) {
            Some(data) => (boxed_vec(data.to_vec()), data.len()),
            None => { return Err(byte::Error::BadInput { err: "Error: parse script" }); }
        };
        Ok((Self {
            amount,
            script,
            script_length,
            address: null_mut(),
            address_length: 0
        }, *offset))
    }
}
