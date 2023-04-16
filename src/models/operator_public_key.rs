use std::io;
use byte::{BytesExt, TryRead};
use crate::consensus::Encodable;
use crate::crypto::UInt384;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct OperatorPublicKey {
    pub data: UInt384,
    pub version: u16,
}

impl OperatorPublicKey {
    pub fn is_basic(&self) -> bool {
        self.version >= 2
    }
    pub fn is_legacy(&self) -> bool {
        self.version < 2
    }
}

impl Encodable for OperatorPublicKey {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        self.data.enc(&mut s);
        Ok(48)
    }
}

impl<'a> TryRead<'a, u16> for OperatorPublicKey {
    fn try_read(bytes: &'a [u8], version: u16) -> byte::Result<(Self, usize)> {
        let data = bytes.read_with::<UInt384>(&mut 0, byte::LE)?;
        Ok((OperatorPublicKey { data, version }, 48))
    }
}
