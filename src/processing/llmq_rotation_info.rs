use crate::{MNListDiff, LLMQSnapshot, UInt256};

#[derive(Debug)]
pub struct LLMQRotationInfo<'a> {
    pub snapshot_at_h_c: LLMQSnapshot<'a>,
    pub snapshot_at_h_2c: LLMQSnapshot<'a>,
    pub snapshot_at_h_3c: LLMQSnapshot<'a>,
    pub snapshot_at_h_4c: Option<LLMQSnapshot<'a>>, // exist only if extra_share is true
    pub mn_list_diff_tip: MNListDiff<'a>,
    pub mn_list_diff_at_h: MNListDiff<'a>,
    pub mn_list_diff_at_h_c: MNListDiff<'a>,
    pub mn_list_diff_at_h_2c: MNListDiff<'a>,
    pub mn_list_diff_at_h_3c: MNListDiff<'a>,
    pub mn_list_diff_at_h_4c: Option<MNListDiff<'a>>, // exist only if extra_share is true
    pub extra_share: bool,
    pub block_hash_list: Vec<UInt256>,
    pub snapshot_list: Vec<LLMQSnapshot<'a>>,
    pub mn_list_diff_list: Vec<MNListDiff<'a>>,
}
