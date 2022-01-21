use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use crate::consensus::Decodable;
use crate::VarInt;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum QuorumSnapshotSkipMode {
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
impl From<u32> for QuorumSnapshotSkipMode {
    fn from(orig: u32) -> Self {
        match orig {
            0 => QuorumSnapshotSkipMode::NoSkipping,
            1 => QuorumSnapshotSkipMode::SkipFirst,
            2 => QuorumSnapshotSkipMode::SkipExcept,
            3 => QuorumSnapshotSkipMode::SkipAll,
            _ => QuorumSnapshotSkipMode::NoSkipping
        }
    }
}

impl<'a> TryRead<'a, Endian> for QuorumSnapshotSkipMode {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        match bytes.read_with::<u32>(&mut 0, LE) {
            Ok(data) => Ok((QuorumSnapshotSkipMode::from(data), 4)),
            Err(_err) => Err(byte::Error::BadInput { err: "Can't read quorum snapshot skip mode" })
        }
    }
}

pub struct QuorumSnapshot {
    // The bitset of nodes already in quarters at the start of cycle at height n
    // (masternodeListSize + 7)/8
    pub member_list: Vec<u8>,
    // Skiplist at height n
    pub skip_list: Vec<u32>,
    //  Mode of the skip list
    pub skip_list_mode: QuorumSnapshotSkipMode,
}
impl<'a> TryRead<'a, Endian> for QuorumSnapshot {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let member_list_size_var_int = match VarInt::consensus_decode(&bytes[*offset..]) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput {err: "member_list_size_var_int"}); }
        };
        *offset += member_list_size_var_int.len();
        let member_list_size = member_list_size_var_int.0 as usize;
        let member_list_num = (member_list_size + 7) / 8;
        let member_list = match bytes.read_with(offset, Bytes::Len(member_list_num)) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let skip_list_mode = match bytes.read_with::<QuorumSnapshotSkipMode>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let skip_list_size = match bytes.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(err) => { return Err(err); }
        };
        let mut skip_list: Vec<u32> = Vec::with_capacity(skip_list_size as usize);
        for _i in 0..skip_list_size {
            skip_list.push(match bytes.read_with::<u32>(offset, LE) {
                Ok(data) => data,
                Err(err) => { return Err(err); }
            });
        }
        Ok((Self {
            member_list,
            skip_list,
            skip_list_mode
        }, *offset))
    }
}

impl QuorumSnapshot {
    pub fn length(&self) -> usize {
        self.member_list.len() + 1 + 2 + self.skip_list.len() * 2
    }
}
