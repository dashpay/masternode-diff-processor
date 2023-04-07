use hashes::hex::{FromHex, ToHex};
use crate::key_bindings::{key_create_from_extended_public_key_data, key_extended_public_key_data};
use crate::keys::KeyKind;

#[test]
fn test_keys() {
    let key_type = KeyKind::ECDSA;
    let extended_public_key_data_string = "3dc2e416b0f9fcfd74fe847ccd80f71cf961e7c4ddede29ce5e4b72a19ebccf2831ba2d803740b52e94ad4d526ff2b4340646b2ce1423545755b5825fabc741d1d74c155d7";
    let extended_public_key_data = Vec::from_hex(extended_public_key_data_string).unwrap();

    let extended_public_key = unsafe { key_create_from_extended_public_key_data(extended_public_key_data.as_ptr(), extended_public_key_data.len(), key_type) };
    println!("extended_public_key: {:?}", extended_public_key);
    let extended_public_key_data = unsafe { key_extended_public_key_data(extended_public_key) };
    println!("extended_public_key_data: {:?}", extended_public_key_data);
    let seed_bytes = unsafe { std::slice::from_raw_parts(extended_public_key_data.ptr, extended_public_key_data.len) };
    println!("extended_public_key_data: {:?}", seed_bytes.to_hex());
    assert_eq!(seed_bytes.to_hex(), extended_public_key_data_string);
}
