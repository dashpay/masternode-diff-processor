use dash_spv_primitives::crypto::UInt128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketAddress {
    pub ip_address: UInt128, //v6, but only v4 supported
    pub port: u16,
}
