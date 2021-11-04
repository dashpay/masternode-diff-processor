
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketAddress {
    pub ip_address: u128, //v6, but only v4 supported
    pub port: u16,
}
