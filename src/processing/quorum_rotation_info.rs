use crate::{MNListDiff, QuorumSnapshot, UInt256};

#[derive(Debug)]
pub struct QuorumRotationInfo<'a> {
    pub snapshot_at_h_c: QuorumSnapshot<'a>,
    pub snapshot_at_h_2c: QuorumSnapshot<'a>,
    pub snapshot_at_h_3c: QuorumSnapshot<'a>,
    pub list_diff_tip: MNListDiff<'a>,
    pub list_diff_at_h: MNListDiff<'a>,
    pub list_diff_at_h_c: MNListDiff<'a>,
    pub list_diff_at_h_2c: MNListDiff<'a>,
    pub list_diff_at_h_3c: MNListDiff<'a>,
    pub extra_share: bool,
    pub snapshot_at_h_4c: Option<QuorumSnapshot<'a>>, // exist only if extra_share is true
    pub list_diff_at_h_4c: Option<MNListDiff<'a>>, // exist only if extra_share is true
    pub block_hash_list: Vec<UInt256>,
    pub snapshot_list: Vec<QuorumSnapshot<'a>>,
    pub mn_list_diff_list: Vec<MNListDiff<'a>>,
}
