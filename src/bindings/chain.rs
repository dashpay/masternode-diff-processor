use crate::common::ChainType;

/// # Safety
#[no_mangle]
pub extern "C" fn chain_magic_number(chain_id: i16) -> u32 {
    ChainType::from(chain_id).magic()
}
