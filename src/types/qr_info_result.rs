use crate::types;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QRInfoResult {
    pub error_status: u8,
    pub result_at_tip: *mut types::MNListDiffResult,
    pub result_at_h: *mut types::MNListDiffResult,
    pub result_at_h_c: *mut types::MNListDiffResult,
    pub result_at_h_2c: *mut types::MNListDiffResult,
    pub result_at_h_3c: *mut types::MNListDiffResult,
    pub result_at_h_4c: *mut types::MNListDiffResult,

    pub snapshot_at_h_c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_2c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_3c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_4c: *mut types::LLMQSnapshot,
    pub extra_share: bool,
    pub last_quorum_per_index: *mut *mut types::LLMQEntry,
    pub last_quorum_per_index_count: usize,
    pub quorum_snapshot_list: *mut *mut types::LLMQSnapshot,
    pub quorum_snapshot_list_count: usize,
    pub mn_list_diff_list: *mut *mut types::MNListDiffResult,
    pub mn_list_diff_list_count: usize,
}

impl Default for QRInfoResult {
    fn default() -> Self {
        Self {
            error_status: 0,
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
            extra_share: false,
            last_quorum_per_index_count: 0,
            last_quorum_per_index: null_mut(),
            quorum_snapshot_list_count: 0,
            quorum_snapshot_list: null_mut(),
            mn_list_diff_list_count: 0,
            mn_list_diff_list: null_mut(),
        }
    }
}

impl QRInfoResult {
    pub fn default_with_error(error: u8) -> Self {
        Self { error_status: error, ..Default::default() }
    }
}
