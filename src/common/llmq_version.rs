use byte::ctx::Endian;
use byte::{BytesExt, TryRead, TryWrite};
use crate::BytesDecodable;
use crate::consensus::Encodable;

#[warn(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub enum LLMQVersion {
    Default = 1,
    Indexed = 2,
    BLSBasicDefault = 3,
    BLSBasicIndexed = 4,
}
impl LLMQVersion {
    pub fn use_bls_legacy(&self) -> bool {
        *self == LLMQVersion::Default || *self == LLMQVersion::Indexed
    }
    pub fn use_rotated_quorums(&self) -> bool {
        *self == LLMQVersion::Indexed || *self == LLMQVersion::BLSBasicIndexed
    }
}

impl From<u16> for LLMQVersion {
    fn from(orig: u16) -> Self {
        match orig {
            1 => LLMQVersion::Default,
            2 => LLMQVersion::Indexed,
            3 => LLMQVersion::BLSBasicDefault,
            4 => LLMQVersion::BLSBasicIndexed,
            _ => LLMQVersion::Default,
        }
    }
}

impl From<LLMQVersion> for u16 {
    fn from(value: LLMQVersion) -> Self {
        match value {
            LLMQVersion::Default => 1,
            LLMQVersion::Indexed => 2,
            LLMQVersion::BLSBasicDefault => 3,
            LLMQVersion::BLSBasicIndexed => 4,
        }
    }
}

impl<'a> TryRead<'a, Endian> for LLMQVersion {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let orig = bytes.read_with::<u16>(offset, endian).unwrap();
        Ok((LLMQVersion::from(orig), 2))
    }
}

impl<'a> TryWrite<Endian> for LLMQVersion {
    fn try_write(self, bytes: &mut [u8], _endian: Endian) -> byte::Result<usize> {
        let orig: u16 = self.into();
        orig.consensus_encode(bytes).unwrap();
        Ok(2)
    }
}
impl<'a> BytesDecodable<'a, LLMQVersion> for LLMQVersion {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<LLMQVersion> {
        match bytes.read_with::<LLMQVersion>(offset, byte::LE) {
            Ok(data) => Some(data),
            Err(_err) => None,
        }
    }
}
