use std::ffi::CStr;
use std::os::raw::c_char;
use crate::chain::common::chain_type::DevnetType;
use crate::common::ChainType;
use crate::types::opaque_key::AsCStringPtr;

/// # Safety
#[no_mangle]
pub extern "C" fn chain_type_index(chain_type: ChainType) -> i16 {
    chain_type.into()
}

#[no_mangle]
pub extern "C" fn chain_type_from_index(index: i16) -> ChainType {
    ChainType::from(index)
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_magic_number(chain_type: ChainType) -> u32 {
    chain_type.magic()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_peer_misbehaving_threshold(chain_type: ChainType) -> usize {
    chain_type.peer_misbehaving_threshold()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_max_proof_of_work_target(chain_type: ChainType) -> u32 {
    chain_type.max_proof_of_work_target()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_allow_min_difficulty_blocks(chain_type: ChainType) -> bool {
    chain_type.allow_min_difficulty_blocks()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_standard_port(chain_type: ChainType) -> u16 {
    chain_type.standard_port()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_standard_dapi_grpc_port(chain_type: ChainType) -> u16 {
    chain_type.standard_dapi_grpc_port()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_standard_dapi_jrpc_port(chain_type: ChainType) -> u16 {
    chain_type.standard_dapi_jrpc_port()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_headers_max_amount(chain_type: ChainType) -> u64 {
    chain_type.header_max_amount()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_transaction_version(chain_type: ChainType) -> u16 {
    chain_type.transaction_version()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_coin_type(chain_type: ChainType) -> u32 {
    chain_type.coin_type()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_devnet_version(devnet_type: DevnetType) -> u16 {
    devnet_type.version()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_devnet_identifier(devnet_type: DevnetType) -> *mut c_char {
    devnet_type.identifier().to_c_string_ptr()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_devnet_from_identifier(identifier: *const c_char) -> DevnetType {
    let c_str = unsafe { CStr::from_ptr(identifier) };
    DevnetType::from(c_str.to_str().unwrap())
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_type_for_devnet_type(devnet_type: DevnetType) -> ChainType {
    ChainType::from(devnet_type)
}

/// # Safety
#[no_mangle]
pub extern "C" fn devnet_type_for_chain_type(chain_type: ChainType) -> DevnetType {
    DevnetType::from(chain_type)
}
