#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub ptr: *mut u8,
    pub length: usize,
}
