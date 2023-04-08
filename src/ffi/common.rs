use std::{mem, ptr, slice, os::raw::c_ulong};
use crate::chain::derivation::{IIndexPath, IndexPath};
use crate::crypto::UInt256;
use crate::util::sec_vec::SecVec;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ByteArray {
    pub ptr: *const u8,
    pub len: usize,
}

impl Default for ByteArray {
    fn default() -> Self {
        ByteArray { ptr: ptr::null(), len: 0 }
    }
}

impl From<blake3::Hash> for ByteArray {
    fn from(value: blake3::Hash) -> Self {
        let bytes: [u8; 32] = value.into();
        let ptr = bytes.as_ptr();
        let len = bytes.len();
        mem::forget(bytes);
        ByteArray { ptr, len }
    }
}

impl From<[u8; 65]> for ByteArray {
    fn from(value: [u8; 65]) -> Self {
        let ptr = value.as_ptr();
        let len = value.len();
        mem::forget(value);
        ByteArray { ptr, len }
    }
}

impl From<Option<[u8; 65]>> for ByteArray {
    fn from(value: Option<[u8; 65]>) -> Self {
        if let Some(v) = value {
            v.into()
        } else {
            ByteArray::default()
        }
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(value: Vec<u8>) -> Self {
        let ptr = value.as_ptr();
        let len = value.len();
        mem::forget(value);
        ByteArray { ptr, len }
    }
}

impl From<Option<Vec<u8>>> for ByteArray {
    fn from(value: Option<Vec<u8>>) -> Self {
        match value {
            Some(vec) => {
                let ptr = vec.as_ptr();
                let len = vec.len();
                mem::forget(vec);
                ByteArray { ptr, len }
            }
            None => ByteArray::default(),
        }
    }
}

impl From<Option<SecVec>> for ByteArray {
    fn from(value: Option<SecVec>) -> Self {
        match value {
            Some(vec) => {
                let ptr = vec.as_ptr();
                let len = vec.len();
                mem::forget(vec);
                ByteArray { ptr, len }
            }
            None => ByteArray::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IndexPathData {
    pub indexes: *const c_ulong,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DerivationPathData {
    pub indexes: *const [u8; 32],
    pub hardened: *const u8,
    pub len: usize,
}


impl From<*const IndexPathData> for IndexPath<u32> {
    fn from(value: *const IndexPathData) -> Self {
        let indexes_slice = unsafe { slice::from_raw_parts((*value).indexes, (*value).len) };
        IndexPath::new(indexes_slice.iter().map(|&index| index as u32).collect())
    }
}

impl From<*const DerivationPathData> for IndexPath<UInt256> {
    fn from(value: *const DerivationPathData) -> Self {
        let indexes_slice = unsafe { slice::from_raw_parts((*value).indexes, (*value).len) };
        let hardened_slice = unsafe { slice::from_raw_parts((*value).hardened, (*value).len) };
        IndexPath::new_hardened(
            indexes_slice.iter().map(|&index| UInt256(index)).collect(),
            hardened_slice.iter().map(|&index| index > 0).collect()
        )
    }
}

// #[repr(C)]
// pub struct SecVecData {
//     data: *const u8,
//     len: usize,
// }
//
// impl From<SecVec> for SecVecData {
//     fn from(sec_vec: SecVec) -> Self {
//         let data = sec_vec.as_ptr();
//         let len = sec_vec.len();
//         mem::forget(sec_vec);
//         SecVecData { data, len }
//     }
// }

