use crate::common::LLMQSnapshotSkipMode;
use crate::masternode::MasternodeEntry;
use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, TryRead, LE};
use dash_spv_primitives::consensus::encode::VarInt;
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use dash_spv_primitives::hashes::hex::ToHex;
use dash_spv_primitives::impl_bytes_decodable;

#[derive(Clone)]
pub struct LLMQSnapshot {
    // The bitset of nodes already in quarters at the start of cycle at height n
    // (masternodeListSize + 7)/8
    pub member_list: Vec<u8>,
    // Skiplist at height n
    pub skip_list: Vec<i32>,
    //  Mode of the skip list
    pub skip_list_mode: LLMQSnapshotSkipMode,
}
impl Default for LLMQSnapshot {
    fn default() -> Self {
        Self {
            member_list: vec![],
            skip_list: vec![],
            skip_list_mode: LLMQSnapshotSkipMode::NoSkipping,
        }
    }
}

impl<'a> std::fmt::Debug for LLMQSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQSnapshot")
            .field("member_list", &self.member_list.to_hex())
            .field("skip_list", &self.skip_list.iter())
            .field("skip_list_mode", &self.skip_list_mode)
            .finish()
    }
}
impl<'a> TryRead<'a, Endian> for LLMQSnapshot {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let skip_list_mode = bytes.read_with::<LLMQSnapshotSkipMode>(offset, LE)?;
        let member_list_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let member_list: &[u8] =
            bytes.read_with(offset, Bytes::Len((member_list_length + 7) / 8))?;
        let skip_list_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let mut skip_list = Vec::with_capacity(skip_list_length);
        for _i in 0..skip_list_length {
            skip_list.push(bytes.read_with::<i32>(offset, LE)?);
        }
        Ok((
            Self {
                member_list: member_list.to_vec(),
                skip_list,
                skip_list_mode,
            },
            *offset,
        ))
    }
}

impl LLMQSnapshot {

    pub fn new(member_list: Vec<u8>, skip_list: Vec<i32>, skip_list_mode: LLMQSnapshotSkipMode) -> Self {
        LLMQSnapshot {
            member_list,
            skip_list,
            skip_list_mode
        }
    }

    pub fn length(&self) -> usize {
        self.member_list.len() + 1 + 2 + self.skip_list.len() * 2
    }

    pub fn apply_skip_strategy(
        &self,
        sorted_combined_mns_list: Vec<MasternodeEntry>,
        quorum_num: usize,
        quarter_size: usize,
    ) -> Vec<Vec<MasternodeEntry>> {
        let mut quarter_quorum_members = Vec::<Vec<MasternodeEntry>>::with_capacity(quorum_num);
        match self.skip_list_mode {
            LLMQSnapshotSkipMode::NoSkipping => {
                let mut iter = sorted_combined_mns_list.iter();
                (0..quorum_num).for_each(|_i| {
                    let mut quarter = Vec::<MasternodeEntry>::new();
                    while quarter.len() < quarter_size {
                        if let Some(node) = iter.next() {
                            quarter.push(node.clone());
                        } else {
                            iter = sorted_combined_mns_list.iter();
                        }
                    }
                    quarter_quorum_members.push(quarter);
                });
            }
            LLMQSnapshotSkipMode::SkipFirst => {
                let mut first_entry_index = 0;
                let mut processed_skip_list = Vec::<i32>::new();
                self.skip_list.iter().for_each(|s| {
                    let index = first_entry_index + s;
                    if first_entry_index == 0 {
                        first_entry_index = *s;
                    }
                    processed_skip_list.push(index)
                });
                let mut index: usize = 0;
                let mut idxk: usize = 0;
                (0..quorum_num).for_each(|_i| {
                    let mut quarter = Vec::<MasternodeEntry>::new();
                    while quarter.len() < quarter_size {
                        if let Some(_skipped) = processed_skip_list.get(idxk) {
                            idxk += 1;
                        } else if let Some(node) = sorted_combined_mns_list.get(index) {
                            quarter.push(node.clone());
                            index += 1;
                            if index == sorted_combined_mns_list.len() {
                                index = 0;
                            }
                        }
                    }
                    quarter_quorum_members.push(quarter);
                });
            }
            LLMQSnapshotSkipMode::SkipExcept => {
                (0..quorum_num).for_each(|_i| {
                    let mut quarter = Vec::<MasternodeEntry>::new();
                    self.skip_list.iter().for_each(|unskipped| {
                        if let Some(node) = sorted_combined_mns_list.get(*unskipped as usize) {
                            if quarter.len() < quarter_size {
                                quarter.push(node.clone());
                            }
                        }
                    });
                    quarter_quorum_members.push(quarter);
                });
            }
            LLMQSnapshotSkipMode::SkipAll => {
                // TODO: do we need to impl smth in this strategy ?
            }
        }
        quarter_quorum_members
    }
}
impl_bytes_decodable!(LLMQSnapshot);
