use std::ffi::c_void;
use std::ptr::null_mut;
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, UInt256};
use crate::{BlockHeightLookup, boxed, processing, ToFFI};
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
        }
    }
}

impl LLMQRotationInfo {
    pub fn new(
        message: &[u8],
        block_height_lookup: BlockHeightLookup,
        context: *const c_void, // External Masternode Manager Diff Message Context ()
    ) -> Option<LLMQRotationInfo> {
        let bh_lookup = |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) };
        let offset = &mut 0;
        let snapshot_at_h_c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_2c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_3c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let mn_list_diff_tip = boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode());
        let mn_list_diff_at_h = boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode());
        let mn_list_diff_at_h_c = boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode());
        let mn_list_diff_at_h_2c = boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode());
        let mn_list_diff_at_h_3c = boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode());
        let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);

        let (snapshot_at_h_4c,
            mn_list_diff_at_h_4c) = if extra_share {
            (boxed(LLMQSnapshot::from_bytes(message, offset)?),
             boxed(processing::MNListDiff::new(message, offset, bh_lookup)?.encode()))
        } else {
            (null_mut(), null_mut())
        };
        Some(Self {
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            snapshot_at_h_4c,
            mn_list_diff_tip,
            mn_list_diff_at_h,
            mn_list_diff_at_h_c,
            mn_list_diff_at_h_2c,
            mn_list_diff_at_h_3c,
            mn_list_diff_at_h_4c,
            extra_share: false
        })
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
        }, *offset))

    }
}
