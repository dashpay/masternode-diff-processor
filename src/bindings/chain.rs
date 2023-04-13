use crate::common::ChainType;

/// # Safety
#[no_mangle]
pub extern "C" fn chain_magic_number(chain_id: i16) -> u32 {
    ChainType::from(chain_id).magic()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_max_proof_of_work_target(chain_id: i16) -> u32 {
    ChainType::from(chain_id).max_proof_of_work_target()
}

/// # Safety
#[no_mangle]
pub extern "C" fn chain_allow_min_difficulty_blocks(chain_id: i16) -> bool {
    ChainType::from(chain_id).allow_min_difficulty_blocks()
}
