use std::os::raw::{c_char, c_void};
use crate::{BLSKey, ECDSAKey, ED25519Key};
use crate::ffi::boxer::boxed;
use crate::keys::KeyType;

pub trait AsOpaque {
    fn as_opaque(&self) -> *mut OpaqueKey;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueKey {
    pub key_type: KeyType,
    // ECDSAKey, ED25519Key or BLSKey
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueKeys {
    pub keys: *mut *mut OpaqueKey,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueSerializedKeys {
    pub keys: *mut *mut c_char,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KeyWithUniqueId {
    pub key_type: KeyType,
    pub unique_id: u64,
    // ECDSAKey, ED25519Key or BLSKey
    pub ptr: *mut c_void,
}


impl AsOpaque for ECDSAKey {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: KeyType::ECDSA, ptr: boxed(self) as *mut c_void })
    }
}

impl AsOpaque for BLSKey {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: if self.use_legacy { KeyType::BLS } else { KeyType::BLSBasic }, ptr: boxed(self) as *mut c_void })
    }
}

impl AsOpaque for ED25519Key {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: KeyType::ED25519, ptr: boxed(self) as *mut c_void })
    }
}






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

