use std::{mem, ptr, slice, os::raw::c_ulong};
use crate::chain::derivation::{IIndexPath, IndexPath};
use crate::crypto::UInt256;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ByteArray {
    pub ptr: *const u8,
    pub len: usize,
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
            None => ByteArray { ptr: ptr::null(), len: 0 },
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


