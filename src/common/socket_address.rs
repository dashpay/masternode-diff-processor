use std::io;
use crate::consensus::Encodable;
use crate::crypto::UInt128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketAddress {
    pub ip_address: UInt128, //v6, but only v4 supported
    pub port: u16,
}

impl Encodable for SocketAddress {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        self.ip_address.enc(&mut s);
        self.port.swap_bytes().enc(&mut s);
        Ok(18)
    }
}
