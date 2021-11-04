use crate::keys::key::Key;

#[repr(C)]
#[derive(Debug)]
pub struct ECDSAKey<'a> {
    pub base: Key<'a>,
    pub secret_key: [u8; 32],
}
