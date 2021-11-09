use crate::crypto::byte_util::UInt256;
use crate::keys::key::Key;

// #[repr(C)]
#[derive(Debug)]
pub struct ECDSAKey<'a> {
    pub base: Key<'a>,
    pub secret_key: UInt256,
}
