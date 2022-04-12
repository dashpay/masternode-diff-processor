use std::ptr::null_mut;
use byte::BytesExt;
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, UInt256};
use crate::{boxed, ffi, FromFFI, LLMQType, Manager, MNListDiffResult, processing};
use crate::ffi::types::{LLMQSnapshot, LLMQValidationData};

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQRotationInfoResult {
    pub result_at_tip: *mut ffi::types::MNListDiffResult,
    pub result_at_h: *mut ffi::types::MNListDiffResult,
    pub result_at_h_c: *mut ffi::types::MNListDiffResult,
    pub result_at_h_2c: *mut ffi::types::MNListDiffResult,
    pub result_at_h_3c: *mut ffi::types::MNListDiffResult,
    pub result_at_h_4c: *mut ffi::types::MNListDiffResult,

    pub snapshot_at_h_c: *mut ffi::types::LLMQSnapshot,
    pub snapshot_at_h_2c: *mut ffi::types::LLMQSnapshot,
    pub snapshot_at_h_3c: *mut ffi::types::LLMQSnapshot,
    pub snapshot_at_h_4c: *mut ffi::types::LLMQSnapshot,
    pub extra_share: bool,
}

impl LLMQRotationInfoResult {
    pub fn from_message<
        MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
        MND: Fn(*const ffi::types::MasternodeList) + Copy,
        AIL: Fn(UInt256) + Copy,
        BHL: Fn(UInt256) -> u32 + Copy,
        SPL: Fn(LLMQType) -> bool + Copy,
        VQL: Fn(LLMQValidationData) -> bool + Copy,
    >(
        message: &[u8],
        merkle_root: UInt256,
        manager: Manager<BHL, MNL, MND, AIL, SPL, VQL>,
    ) -> Option<Self> {
        let offset = &mut 0;
        let snapshot_at_h_c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_2c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_3c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let diff_tip = processing::MNListDiff::new(message, offset, manager.block_height_lookup)?;
        let diff_h = processing::MNListDiff::new(message, offset, manager.block_height_lookup)?;
        let diff_h_c = processing::MNListDiff::new(message, offset, manager.block_height_lookup)?;
        let diff_h_2c = processing::MNListDiff::new(message, offset, manager.block_height_lookup)?;
        let diff_h_3c = processing::MNListDiff::new(message, offset, manager.block_height_lookup)?;
        let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);

        let (snapshot_at_h_4c,
            diff_h_4c) = if extra_share {
            (boxed(LLMQSnapshot::from_bytes(message, offset)?),
             Some(processing::MNListDiff::new(message, offset, manager.block_height_lookup)?))
        } else {
            (null_mut(), None)
        };

        let result_at_tip = boxed(MNListDiffResult::from_diff(diff_tip, manager, merkle_root));
        let result_at_h = boxed(MNListDiffResult::from_diff(diff_h, manager, merkle_root));
        let result_at_h_c = boxed(MNListDiffResult::from_diff(diff_h_c, manager, merkle_root));
        let result_at_h_2c = boxed(MNListDiffResult::from_diff(diff_h_2c, manager, merkle_root));
        let result_at_h_3c = boxed(MNListDiffResult::from_diff(diff_h_3c, manager, merkle_root));
        let result_at_h_4c = if extra_share {
            boxed(MNListDiffResult::from_diff(diff_h_4c.unwrap(), manager, merkle_root))
        } else {
            null_mut()
        };

        Some(Self {
            result_at_tip,
            result_at_h,
            result_at_h_c,
            result_at_h_2c,
            result_at_h_3c,
            result_at_h_4c,
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            snapshot_at_h_4c,
            extra_share
        })
    }

    pub fn new<
        BHL: Fn(UInt256) -> u32 + Copy,
        MNL: Fn(UInt256) -> *const ffi::types::MasternodeList + Copy,
        MND: Fn(*const ffi::types::MasternodeList) + Copy,
        AIL: Fn(UInt256) + Copy,
        SPL: Fn(LLMQType) -> bool + Copy,
        VQL: Fn(LLMQValidationData) -> bool + Copy,
    >(
        info: ffi::types::LLMQRotationInfo,
        manager: Manager<BHL, MNL, MND, AIL, SPL, VQL>,
        merkle_root: UInt256,
    ) -> Self {
        let extra_share = info.extra_share;
        let result_at_tip = boxed(MNListDiffResult::from_diff(unsafe { (*(info.mn_list_diff_tip)).decode() }, manager, merkle_root));
        let result_at_h = boxed(MNListDiffResult::from_diff(unsafe { (*(info.mn_list_diff_at_h)).decode() }, manager, merkle_root ));
        let result_at_h_c = boxed(MNListDiffResult::from_diff(unsafe { (*(info.mn_list_diff_at_h_c)).decode() }, manager, merkle_root));
        let result_at_h_2c = boxed(MNListDiffResult::from_diff(unsafe { (*(info.mn_list_diff_at_h_2c)).decode() }, manager, merkle_root));
        let result_at_h_3c = boxed(MNListDiffResult::from_diff(unsafe { (*(info.mn_list_diff_at_h_3c)).decode() }, manager, merkle_root));
        let result_at_h_4c = if extra_share {
            let list_diff = unsafe { (*(info.mn_list_diff_at_h_4c)).decode() };
            let result = MNListDiffResult::from_diff(list_diff, manager, merkle_root);
            boxed(result)
        } else {
            null_mut()
        };
        Self {
            result_at_tip,
            result_at_h,
            result_at_h_c,
            result_at_h_2c,
            result_at_h_3c,
            result_at_h_4c,
            snapshot_at_h_c: info.snapshot_at_h_c,
            snapshot_at_h_2c: info.snapshot_at_h_2c,
            snapshot_at_h_3c: info.snapshot_at_h_3c,
            snapshot_at_h_4c: info.snapshot_at_h_4c,
            extra_share
        }
    }
}

impl Default for LLMQRotationInfoResult {
    fn default() -> Self {
        Self {
            result_at_tip: null_mut(),
            result_at_h: null_mut(),
            result_at_h_c: null_mut(),
            result_at_h_2c: null_mut(),
            result_at_h_3c: null_mut(),
            result_at_h_4c: null_mut(),
            snapshot_at_h_c: null_mut(),
            snapshot_at_h_2c: null_mut(),
            snapshot_at_h_3c: null_mut(),
            snapshot_at_h_4c: null_mut(),
            extra_share: false
        }
    }
}
