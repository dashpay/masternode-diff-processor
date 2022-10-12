use crate::ffi::boxer::{boxed, boxed_vec};
use crate::types::llmq_snapshot::LLMQSnapshot;
use crate::types::mn_list_diff::MNListDiff;
use crate::types::LLMQEntry;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QRInfo {
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
    pub last_quorum_per_index: *mut *mut LLMQEntry,
    pub last_quorum_per_index_count: usize,
    pub quorum_snapshot_list: *mut *mut LLMQSnapshot,
    pub quorum_snapshot_list_count: usize,
    pub mn_list_diff_list: *mut *mut MNListDiff,
    pub mn_list_diff_list_count: usize,
}

impl Default for QRInfo {
    fn default() -> Self {
        QRInfo {
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
            last_quorum_per_index: null_mut(),
            last_quorum_per_index_count: 0,
            quorum_snapshot_list: null_mut(),
            quorum_snapshot_list_count: 0,
            mn_list_diff_list: null_mut(),
            mn_list_diff_list_count: 0,
        }
    }
}

impl<'a> TryRead<'a, Endian> for QRInfo {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
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
        let (snapshot_at_h_4c, mn_list_diff_at_h_4c) = if extra_share {
            (
                boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?),
                boxed(bytes.read_with::<MNListDiff>(offset, LE)?),
            )
        } else {
            (null_mut(), null_mut())
        };
        let last_quorum_per_index_count = bytes
            .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
            .0 as usize;
        let mut last_quorum_per_index_vec: Vec<*mut LLMQEntry> =
            Vec::with_capacity(last_quorum_per_index_count as usize);
        for _i in 0..last_quorum_per_index_count {
            last_quorum_per_index_vec.push(boxed(bytes.read_with::<LLMQEntry>(offset, LE)?));
        }
        let last_quorum_per_index = boxed_vec(last_quorum_per_index_vec);

        let quorum_snapshot_list_count = bytes
            .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
            .0 as usize;
        let mut quorum_snapshot_list_vec: Vec<*mut LLMQSnapshot> =
            Vec::with_capacity(quorum_snapshot_list_count as usize);
        for _i in 0..quorum_snapshot_list_count {
            quorum_snapshot_list_vec.push(boxed(bytes.read_with::<LLMQSnapshot>(offset, LE)?));
        }
        let quorum_snapshot_list = boxed_vec(quorum_snapshot_list_vec);

        let mn_list_diff_list_count = bytes
            .read_with::<dash_spv_primitives::consensus::encode::VarInt>(offset, LE)?
            .0 as usize;
        let mut mn_list_diff_list_vec: Vec<*mut MNListDiff> =
            Vec::with_capacity(mn_list_diff_list_count as usize);
        for _i in 0..mn_list_diff_list_count {
            mn_list_diff_list_vec.push(boxed(bytes.read_with::<MNListDiff>(offset, LE)?));
        }
        let mn_list_diff_list = boxed_vec(mn_list_diff_list_vec);

        Ok((
            Self {
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
                last_quorum_per_index_count,
                last_quorum_per_index,
                quorum_snapshot_list_count,
                quorum_snapshot_list,
                mn_list_diff_list_count,
                mn_list_diff_list,
            },
            *offset,
        ))
    }
}
