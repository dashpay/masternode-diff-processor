use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use dash_spv_models::common::llmq_snapshot_skip_mode::LLMQSnapshotSkipMode;
use dash_spv_primitives::consensus::encode::VarInt;

#[derive(Clone, Debug)]
pub struct LLMQSnapshot<'a> {
    // The bitset of nodes already in quarters at the start of cycle at height n
    // (masternodeListSize + 7)/8
    pub member_list: &'a [u8],
    // Skiplist at height n
    pub skip_list: Vec<u32>,
    //  Mode of the skip list
    pub skip_list_mode: LLMQSnapshotSkipMode,
}
impl<'a> TryRead<'a, Endian> for LLMQSnapshot<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let member_list_size = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let member_list = bytes.read_with(offset, Bytes::Len((member_list_size + 7) / 8))?;
        let skip_list_mode = bytes.read_with::<LLMQSnapshotSkipMode>(offset, LE)?;
        let skip_list_size = bytes.read_with::<u16>(offset, LE)? as usize;
        let mut skip_list = Vec::with_capacity(skip_list_size);
        for _i in 0..skip_list_size {
            skip_list.push(bytes.read_with::<u32>(offset, LE)?);
        }
        Ok((Self {
            member_list,
            skip_list,
            skip_list_mode
        }, *offset))
    }
}

impl<'a> LLMQSnapshot<'a> {
    pub fn length(&self) -> usize {
        self.member_list.len() + 1 + 2 + self.skip_list.len() * 2
    }
}
