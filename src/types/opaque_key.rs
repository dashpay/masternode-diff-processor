use std::os::raw::{c_char, c_void};
use std::ptr::null_mut;
use crate::{BLSKey, ECDSAKey, ED25519Key};
use crate::ffi::boxer::boxed;
use crate::keys::KeyKind;

pub trait AsOpaque {
    fn as_opaque(&self) -> *mut OpaqueKey;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpaqueKey {
    pub key_type: KeyKind,
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
    pub key_type: KeyKind,
    pub unique_id: u64,
    // ECDSAKey, ED25519Key or BLSKey
    pub ptr: *mut c_void,
}


impl AsOpaque for ECDSAKey {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: KeyKind::ECDSA, ptr: boxed(self) as *mut c_void })
    }
}

impl AsOpaque for BLSKey {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: if self.use_legacy { KeyKind::BLS } else { KeyKind::BLSBasic }, ptr: boxed(self) as *mut c_void })
    }
}

impl AsOpaque for ED25519Key {
    fn as_opaque(&self) -> *mut OpaqueKey {
        boxed(OpaqueKey { key_type: KeyKind::ED25519, ptr: boxed(self) as *mut c_void })
    }
}

impl AsOpaque for Option<ECDSAKey> {
    fn as_opaque(&self) -> *mut OpaqueKey {
        if let Some(key) = self {
            key.as_opaque()
        } else {
            null_mut()
        }
    }
}

impl AsOpaque for Option<BLSKey> {
    fn as_opaque(&self) -> *mut OpaqueKey {
        if let Some(key) = self {
            key.as_opaque()
        } else {
            null_mut()
        }
    }
}

impl AsOpaque for Option<ED25519Key> {
    fn as_opaque(&self) -> *mut OpaqueKey {
        if let Some(key) = self {
            key.as_opaque()
        } else {
            null_mut()
        }
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


