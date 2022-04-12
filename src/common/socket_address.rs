use dash_spv_primitives::crypto::byte_util::UInt128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketAddress {
    pub ip_address: UInt128, //v6, but only v4 supported
    pub port: u16,
}
