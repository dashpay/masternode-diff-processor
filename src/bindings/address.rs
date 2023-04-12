use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
use crate::chain::ScriptMap;
use crate::crypto::byte_util::ConstDecodable;
use crate::crypto::UInt160;
use crate::ffi::ByteArray;
use crate::types::opaque_key::AsCStringPtr;
use crate::util::address::address;
use crate::util::data_append::DataAppend;

/// # Safety
#[no_mangle]
pub extern "C" fn address_from_hash160(hash: *const u8, chain_id: i16) -> *mut c_char {
    let hash = UInt160::from_const(hash).unwrap_or(UInt160::MIN);
    let script_map = ScriptMap::from(chain_id);
    address::from_hash160_for_script_map(&hash, &script_map)
        .to_c_string_ptr()
}

/// # Safety
#[no_mangle]
pub extern "C" fn address_with_script_pubkey(script: *const u8, script_len: usize, chain_id: i16) -> *mut c_char {
    let script = unsafe { slice::from_raw_parts(script, script_len) };
    let script_map = ScriptMap::from(chain_id);
    address::with_script_pub_key(&script.to_vec(), &script_map)
        .to_c_string_ptr()
}

/// # Safety
#[no_mangle]
pub extern "C" fn address_with_script_sig(script: *const u8, script_len: usize, chain_id: i16) -> *mut c_char {
    let script = unsafe { slice::from_raw_parts(script, script_len) };
    let script_map = ScriptMap::from(chain_id);
    address::with_script_sig(&script.to_vec(), &script_map)
        .to_c_string_ptr()
}

/// # Safety
#[no_mangle]
pub extern "C" fn script_pubkey_for_address(address: *const c_char, chain_id: i16) -> ByteArray {
    let c_str = unsafe { CStr::from_ptr(address) };
    let script_map = ScriptMap::from(chain_id);
    Vec::<u8>::script_pub_key_for_address(c_str.to_str().unwrap(), &script_map).into()
}

/// # Safety
#[no_mangle]
pub extern "C" fn is_valid_dash_address_for_chain(address: *const c_char, chain_id: i16) -> bool {
    let c_str = unsafe { CStr::from_ptr(address) };
    let script_map = ScriptMap::from(chain_id);
    address::is_valid_dash_address_for_script_map(c_str.to_str().unwrap(), &script_map)
}
