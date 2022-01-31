use std::ffi::c_void;
use crate::ffi::types::masternode_list::MasternodeList;
use crate::ffi::types::llmq_validation_data::LLMQValidationData;

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessLLMQTypeCallback = unsafe extern "C" fn(llmq_type: u8, context: *const c_void) -> bool;
pub type ValidateLLMQCallback = unsafe extern "C" fn(data: *mut LLMQValidationData, context: *const c_void) -> bool;

pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(*const MasternodeList);
