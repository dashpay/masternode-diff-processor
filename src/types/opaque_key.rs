use crate::{BLSKey, ECDSAKey, ED25519Key};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ECDSAKeyWithUniqueId {
    pub unique_id: u64,
    pub ptr: *mut ECDSAKey,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ED25519KeyWithUniqueId {
    pub unique_id: u64,
    pub ptr: *mut ED25519Key,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BLSKeyWithUniqueId {
    pub unique_id: u64,
    pub ptr: *mut BLSKey,
}
