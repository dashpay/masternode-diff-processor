use std::ffi::c_void;
use std::ptr::null_mut;
use byte::BytesExt;
use crate::{AddInsightBlockingLookup, BlockHeightLookup, boxed, ffi, FromFFI, MasternodeListDestroy, MasternodeListLookup, processing, ShouldProcessLLMQTypeCallback, UInt256, ValidateLLMQCallback};
use crate::crypto::byte_util::BytesDecodable;
use crate::ffi::types::LLMQSnapshot;

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
    pub fn from_message(
        message: &[u8],
        merkle_root: UInt256,
        base_masternode_list: *const ffi::types::MasternodeList,
        masternode_list_lookup: MasternodeListLookup,
        masternode_list_destroy: MasternodeListDestroy,
        use_insight_as_backup: bool,
        add_insight_lookup: AddInsightBlockingLookup,
        should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
        validate_llmq_callback: ValidateLLMQCallback,
        block_height_lookup: BlockHeightLookup,
        context: *const c_void, // External Masternode Manager Diff Message Context ()
    ) -> Option<Self> {
        let bh_lookup = |h: UInt256| unsafe { block_height_lookup(boxed(h.0), context) };
        let offset = &mut 0;
        let snapshot_at_h_c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_2c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let snapshot_at_h_3c = boxed(LLMQSnapshot::from_bytes(message, offset)?);
        let diff_tip = processing::MNListDiff::new(message, offset, bh_lookup)?;
        let diff_h = processing::MNListDiff::new(message, offset, bh_lookup)?;
        let diff_h_c = processing::MNListDiff::new(message, offset, bh_lookup)?;
        let diff_h_2c = processing::MNListDiff::new(message, offset, bh_lookup)?;
        let diff_h_3c = processing::MNListDiff::new(message, offset, bh_lookup)?;
        let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);

        let (snapshot_at_h_4c,
            diff_h_4c) = if extra_share {
            (boxed(LLMQSnapshot::from_bytes(message, offset)?),
             Some(processing::MNListDiff::new(message, offset, bh_lookup)?))
        } else {
            (null_mut(), None)
        };

        let result_at_tip = boxed(ffi::types::MNListDiffResult::from_diff(
            diff_tip,
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h = boxed(ffi::types::MNListDiffResult::from_diff(
            diff_h,
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_c = boxed(ffi::types::MNListDiffResult::from_diff(
            diff_h_c,
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_2c = boxed(ffi::types::MNListDiffResult::from_diff(
            diff_h_2c,
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_3c = boxed(ffi::types::MNListDiffResult::from_diff(
            diff_h_3c,
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_4c = if extra_share { boxed(ffi::types::MNListDiffResult::from_diff(
            diff_h_4c.unwrap(),
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        )) } else { null_mut() };


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

    pub fn new(
        info: ffi::types::LLMQRotationInfo,
        base_masternode_list: *const ffi::types::MasternodeList,
        masternode_list_lookup: MasternodeListLookup,
        masternode_list_destroy: MasternodeListDestroy,
        merkle_root: UInt256,
        use_insight_as_backup: bool,
        add_insight_lookup: AddInsightBlockingLookup,
        should_process_llmq_of_type: ShouldProcessLLMQTypeCallback,
        validate_llmq_callback: ValidateLLMQCallback,
        block_height_lookup: BlockHeightLookup,
        context: *const c_void, // External Masternode Manager Diff Message Context ()

    ) -> Self {
        let extra_share = info.extra_share;
        let result_at_tip = boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_tip)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h = boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_at_h)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_c = boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_at_h_c)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_2c = boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_at_h_2c)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));
        let result_at_h_3c = boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_at_h_3c)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        ));

        let result_at_h_4c = if extra_share { boxed(ffi::types::MNListDiffResult::from_diff(
            unsafe { (*(info.mn_list_diff_at_h_4c)).decode() },
            masternode_list_lookup, masternode_list_destroy,
            merkle_root, use_insight_as_backup, add_insight_lookup,
            should_process_llmq_of_type, validate_llmq_callback,
            block_height_lookup, context
        )) } else { null_mut() };

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
