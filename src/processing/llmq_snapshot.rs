use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use crate::VarInt;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum LLMQSnapshotSkipMode {
    // No skipping. The skip list is empty.
    NoSkipping = 0,
    // Skip the first entry of the list.
    // The following entries contain the relative position of subsequent skips.
    // For example, if during the initialization phase you skip entries x, y and z of the masternode
    // list, the skip list will contain x, y-x and z-y in this mode.
    SkipFirst = 1,
    // Contains the entries which were not skipped.
    // This is better when there are many skips.
    // Mode 2 is more efficient and should be used when 3/4*quorumSize ≥ 1/2*masternodeNb or
    // quorumsize ≥ 2/3*masternodeNb
    SkipExcept = 2,
    // Every node was skipped. The skip list is empty. DKG sessions were not attempted.
    SkipAll = 3
}
impl From<u32> for LLMQSnapshotSkipMode {
    fn from(orig: u32) -> Self {
        match orig {
            0 => LLMQSnapshotSkipMode::NoSkipping,
            1 => LLMQSnapshotSkipMode::SkipFirst,
            2 => LLMQSnapshotSkipMode::SkipExcept,
            3 => LLMQSnapshotSkipMode::SkipAll,
            _ => LLMQSnapshotSkipMode::NoSkipping
        }
    }
}

impl<'a> TryRead<'a, Endian> for LLMQSnapshotSkipMode {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        Ok((LLMQSnapshotSkipMode::from(bytes.read_with::<u32>(&mut 0, LE)?), 4))
    }
}

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
