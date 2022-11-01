#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LLMQValidationData {
    pub items: *mut *mut [u8; 48],
    pub count: usize,
    pub commitment_hash: *mut [u8; 32],
    pub all_commitment_aggregated_signature: *mut [u8; 96],
    pub threshold_signature: *mut [u8; 96],
    pub public_key: *mut [u8; 48],
}
