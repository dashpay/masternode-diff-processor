use dash_spv_models::common::LLMQSnapshotSkipMode;
use dash_spv_models::llmq::LLMQSnapshot;
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use dash_spv_primitives::crypto::data_ops::Data;
use dash_spv_primitives::hashes::hex::FromHex;

#[test]
pub fn test_quorum_snapshot() {
    let payload = Vec::from_hex("000000001fb95e7b0300").unwrap();
    let snapshot = LLMQSnapshot::from_bytes(payload.as_slice(), &mut 0).unwrap();
    println!("snapshot: {:?}", snapshot);
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(0));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(1));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(2));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(3));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(4));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(5));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(6));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(7));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(8));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(9));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(10));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(11));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(12));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(13));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(14));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(15));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(16));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(17));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(18));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(19));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(20));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(21));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(22));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(23));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(24));
    assert_eq!(true, snapshot.member_list.as_slice().bit_is_true_at_le_index(25));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(26));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(27));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(28));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(29));
    assert_eq!(false, snapshot.member_list.as_slice().bit_is_true_at_le_index(30));
    assert_eq!(LLMQSnapshotSkipMode::NoSkipping, snapshot.skip_list_mode);
    assert_eq!(0, snapshot.skip_list.len());
}
