use std::ptr::null_mut;
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use crate::{boxed, boxed_vec, UInt256};
use crate::ffi::types::mn_list_diff::MNListDiff;
use crate::ffi::types::llmq_snapshot::LLMQSnapshot;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQRotationInfo {
    pub snapshot_at_h_c: *mut LLMQSnapshot,
    pub snapshot_at_h_2c: *mut LLMQSnapshot,
    pub snapshot_at_h_3c: *mut LLMQSnapshot,
    pub snapshot_at_h_4c: *mut LLMQSnapshot, // exist only if extra_share is true
    pub mn_list_diff_tip: *mut MNListDiff,
    pub mn_list_diff_at_h: *mut MNListDiff,
    pub mn_list_diff_at_h_c: *mut MNListDiff,
    pub mn_list_diff_at_h_2c: *mut MNListDiff,
    pub mn_list_diff_at_h_3c: *mut MNListDiff,
    pub mn_list_diff_at_h_4c: *mut MNListDiff, // exist only if extra_share is true
    pub extra_share: bool,
    pub block_hash_list_num: u32,
    pub block_hash_list: *mut *mut [u8; 32],
    pub snapshot_list_num: u32,
    pub snapshot_list: *mut *mut LLMQSnapshot,
    pub mn_list_diff_list_num: u32,
    pub mn_list_diff_list: *mut *mut MNListDiff,
}

impl Default for LLMQRotationInfo {
    fn default() -> Self {
        LLMQRotationInfo {
            snapshot_at_h_c: null_mut(),
            snapshot_at_h_2c: null_mut(),
            snapshot_at_h_3c: null_mut(),
            mn_list_diff_tip: null_mut(),
            mn_list_diff_at_h: null_mut(),
            mn_list_diff_at_h_c: null_mut(),
            mn_list_diff_at_h_2c: null_mut(),
            mn_list_diff_at_h_3c: null_mut(),
            extra_share: false,
            snapshot_at_h_4c: null_mut(),
            mn_list_diff_at_h_4c: null_mut(),
            block_hash_list_num: 0,
            block_hash_list: null_mut(),
            snapshot_list_num: 0,
            snapshot_list: null_mut(),
            mn_list_diff_list_num: 0,
            mn_list_diff_list: null_mut()
        }
    }
}

impl<'a> TryRead<'a, Endian> for LLMQRotationInfo {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let snapshot_at_h_c = boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?);
        let snapshot_at_h_2c = boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?);
        let snapshot_at_h_3c = boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?);
        let mn_list_diff_tip = boxed(bytes.read_with::<MNListDiff>(offset, LE)?);
        let mn_list_diff_at_h = boxed(bytes.read_with::<MNListDiff>(offset, LE)?);
        let mn_list_diff_at_h_c = boxed(bytes.read_with::<MNListDiff>(offset, LE)?);
        let mn_list_diff_at_h_2c = boxed(bytes.read_with::<MNListDiff>(offset, LE)?);
        let mn_list_diff_at_h_3c = boxed(bytes.read_with::<MNListDiff>(offset, LE)?);
        let extra_share = bytes.read_with::<bool>(offset, {})?;
        let (snapshot_at_h_4c,
            mn_list_diff_at_h_4c) = if extra_share {
            (boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?),
             boxed(bytes.read_with::<MNListDiff>(offset, LE)?))
        } else {
            (null_mut(), null_mut())
        };
        let block_hash_list_num = bytes.read_with::<u32>(offset, LE)?;
        let mut block_hash_list_vec: Vec<*mut [u8; 32]> = Vec::with_capacity(block_hash_list_num as usize);
        for _i in 0..block_hash_list_num {
            block_hash_list_vec.push(boxed(bytes.read_with::<UInt256>(offset, LE)?.0));
        }
        let snapshot_list_num = bytes.read_with::<u32>(offset, LE)?;
        let mut snapshot_list_vec: Vec<*mut LLMQSnapshot> = Vec::with_capacity(snapshot_list_num as usize);
        for _i in 0..snapshot_list_num {
            snapshot_list_vec.push(boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?));
        }
        let mn_list_diff_list_num = bytes.read_with::<u32>(offset, LE)?;
        let mut mn_list_diff_list_vec: Vec<*mut MNListDiff> = Vec::with_capacity(mn_list_diff_list_num as usize);
        for _i in 0..mn_list_diff_list_num {
            mn_list_diff_list_vec.push(boxed(bytes.read_with::<MNListDiff>(offset, LE)?));
        }
        Ok((Self {
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            mn_list_diff_tip,
            mn_list_diff_at_h,
            mn_list_diff_at_h_c,
            mn_list_diff_at_h_2c,
            mn_list_diff_at_h_3c,
            extra_share,
            snapshot_at_h_4c,
            mn_list_diff_at_h_4c,
            block_hash_list_num,
            block_hash_list: boxed_vec(block_hash_list_vec),
            snapshot_list_num,
            snapshot_list: boxed_vec(snapshot_list_vec),
            mn_list_diff_list_num,
            mn_list_diff_list: boxed_vec(mn_list_diff_list_vec)
        }, *offset))

    }
}
