use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use crate::boxed_vec;
use crate::processing::llmq_snapshot::LLMQSnapshotSkipMode;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQSnapshot {
    pub member_list_length: usize,
    pub member_list: *mut u8,
    // Skip list at height n
    pub skip_list_length: usize,
    pub skip_list: *mut u32,
    //  Mode of the skip list
    pub skip_list_mode: LLMQSnapshotSkipMode,
}
impl<'a> TryRead<'a, Endian> for LLMQSnapshot {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let member_list_length = bytes.read_with::<crate::consensus::encode::VarInt>(offset, LE)?.0 as usize;
        let member_list: &[u8] = bytes.read_with(offset, Bytes::Len((member_list_length + 7) / 8))?;
        let skip_list_mode = bytes.read_with::<LLMQSnapshotSkipMode>(offset, LE)?;
        let skip_list_length = bytes.read_with::<u16>(offset, LE)? as usize;
        let mut skip_list_vec = Vec::with_capacity(skip_list_length);
        for _i in 0..skip_list_length {
            skip_list_vec.push(bytes.read_with::<u32>(offset, LE)?);
        }
        Ok((Self {
            member_list_length,
            member_list: boxed_vec(member_list.to_vec()),
            skip_list_length,
            skip_list: boxed_vec(skip_list_vec),
            skip_list_mode
        }, *offset))
    }
}
