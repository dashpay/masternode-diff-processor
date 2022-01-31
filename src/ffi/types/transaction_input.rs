use std::ptr::null_mut;
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use crate::{boxed, boxed_vec, UInt256};
use crate::crypto::byte_util::data_at_offset_from;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct TransactionInput {
    pub input_hash: *mut [u8; 32],
    pub index: u32,
    pub script: *mut u8,
    pub script_length: usize,
    pub signature: *mut u8,
    pub signature_length: usize,
    pub sequence: u32,
}
impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = bytes.read_with::<u32>(offset, LE)?;
        let (signature, signature_length) = match data_at_offset_from(bytes, offset) {
            Some(data) => (boxed_vec(data.to_vec()), data.len()),
            None => (null_mut(), 0)
        };
        let sequence = bytes.read_with::<u32>(offset, LE)?;
        Ok((Self {
            input_hash: boxed(input_hash.0),
            index,
            script: null_mut(),
            script_length: 0,
            signature,
            signature_length,
            sequence
        }, *offset))
    }
}
