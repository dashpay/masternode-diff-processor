use byte::{BytesExt, check_len, LE, Result, TryRead, TryWrite};
use byte::ctx::{Bytes, Endian};
use std::fmt::Write;
use crate::consensus::{Decodable, Encodable};
use crate::consensus::encode::VarInt;
use crate::hashes::{Hash, sha256d};

pub trait Data {
    // fn address_from_hash_160_data_for_chain(&self, chain: Chain) -> &str;
    // fn base_58_check(&self) -> &str;
    // fn base_58_string(&self) -> &str;
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    // fn data_at_offset_from<'a>(&self, offset: &mut usize) -> Result<&'a [u8]>;
    fn true_bits_count(&self) -> u64;
}

impl Data for [u8] {
    /*fn address_from_hash_160_data_for_chain(&self, chain: Chain) -> &str {
        assert!(self.len(), 20);
        //if self.len() != 20 { None }
        const BUFFER_LENGTH: usize = 1 + self.len() + 4;
        let mut buf = [0u8; BUFFER_LENGTH];
        let offset: &mut usize = &mut 0;
        let v: u8 = if chain.is_main_net() { DASH_PUBKEY_ADDRESS } else { DASH_PUBKEY_ADDRESS_TEST };
        buf.write(offset, v);
        buf.write(offset, self);
        buf.write(offset, sha256_2(&buf) as u32);
        buf.base_58_string()
    }

    fn base_58_check(&self) -> &str {
        let mut v = Vec::with_capacity(self.len() + 4);
        Secret::random();
        const LENGTH: usize = self.len() + 4;
        Secret::<&[u8]>::random(|mut buf | {
            let offset: &mut usize = &mut 0;
            buf.write(offset, &self);
            buf.write(offset, sha256d::Hash::hash(&buf) as u32);
            buf.base_58_string()
        })
    }

    fn base_58_string(&self) -> &str {
        &encode_slice(&self)
    }*/

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, LE).unwrap();
            for _j in 0..8 {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
    }
}


pub fn hex_with_data(data: &[u8]) -> &str {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let mut iter = data.iter();
    while let Some(a) = iter.next() {
        write!(s, "{:02X}", a);
    }
    &s
}

#[inline]
pub fn data_at_offset_from<'a>(buffer: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let var_int: VarInt = match VarInt::consensus_decode(&buffer[*offset..]) {
        Ok(data) => data,
        Err(_error) => {
            return byte::Result::Err(byte::Error::Incomplete);
        }
    };
    let size: usize = var_int.0 as usize + var_int.len();
    *offset += size;
    let data: &[u8] = match buffer.read_with(offset, Bytes::Len(size)) {
        Ok(data) => data,
        Err(error) => { return byte::Result::Err(error); }
    };
    Ok(data)
}

pub fn merkle_root_from_hashes(hashes: Vec<UInt256>) -> Option<UInt256> {
    let length = hashes.len();
    let mut level = hashes.clone();
    if length == 0 { return None; }
    if length == 1 { return Some(hashes[0]); }
    let mut higher_level: Vec<UInt256> = vec![];
    while hashes.len() != 1 {
        for i in (0..level.len()).step_by(2) {
            let left = level[i];
            let mut offset = &mut 0;
            let mut combo = &[0u8; 64];
            combo.write(offset, left);
            combo.write(offset, if level.len() - i > 1 { level[i+1] } else { left });


            /*let mut combined: Vec<sha256d::Hash> = vec![left];
            if level.len() - i > 1 {
                combined.push(level[i + 1]);
            } else {
                combined.push(left);
            }*/


            higher_level.push(UInt256(sha256d::Hash::hash(combo).into_inner()));
        }
        level = higher_level.clone();
        higher_level.clear();
    }
    return Some(level[0]);
}

pub fn short_hex_string_from(data: &[u8]) -> &str {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        &hex_data[..7]
    } else {
        hex_data
    }
}

impl<'a> TryWrite for &'a VarInt {
    #[inline]
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> Result<usize> {
        check_len(bytes, self.len())?;
        Ok(match self.consensus_encode(bytes) {
            Ok(size) => size,
            _ => 0
        })
    }
}

pub const MN_ENTRY_PAYLOAD_LENGTH: usize = 151;

pub trait Reversable {
    fn reversed(&mut self) -> Self;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt128(pub [u8; 16]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt160(pub [u8; 20]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct UInt256(pub [u8; 32]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt384(pub [u8; 48]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt768(pub [u8; 96]);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MNPayload(pub [u8; MN_ENTRY_PAYLOAD_LENGTH]);

impl<'a> TryRead<'a, Endian> for UInt128 {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; 16] = [0u8; 16];
        for _i in 0..16 {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((UInt128(data), 16))
    }
}

impl<'a> TryWrite<Endian> for UInt128 {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(16)
    }
}

impl std::fmt::Display for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for ch in &self.0 {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}


impl<'a> TryRead<'a, Endian> for UInt160 {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; 20] = [0u8; 20];
        for _i in 0..20 {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((UInt160(data), 20))
    }
}

impl<'a> TryWrite<Endian> for UInt160 {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(20)
    }
}

impl<'a> TryRead<'a, Endian> for UInt256 {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; 32] = [0u8; 32];
        for _i in 0..32 {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((UInt256(data), 32))
    }
}

impl<'a> TryWrite<Endian> for UInt256 {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(32)
    }
}

impl std::fmt::Display for UInt256 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for ch in &self.0 {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl Reversable for UInt256 {
    fn reversed(&mut self) -> Self {
        self.0.reverse();
        *self
    }
}

impl<'a> TryRead<'a, Endian> for UInt384 {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; 48] = [0u8; 48];
        for _i in 0..48 {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((UInt384(data), 48))
    }
}

impl<'a> TryWrite<Endian> for UInt384 {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(48)
    }
}

impl<'a> TryRead<'a, Endian> for UInt768 {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; 96] = [0u8; 96];
        for _i in 0..96 {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((UInt768(data), 48))
    }
}

impl<'a> TryWrite<Endian> for UInt768 {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(96)
    }
}

impl<'a> TryRead<'a, Endian> for MNPayload {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let mut data: [u8; MN_ENTRY_PAYLOAD_LENGTH] = [0u8; MN_ENTRY_PAYLOAD_LENGTH];
        for _i in 0..MN_ENTRY_PAYLOAD_LENGTH {
            data[*offset] = bytes.read_with::<u8>(offset, endian).unwrap();
        }
        Ok((MNPayload(data), MN_ENTRY_PAYLOAD_LENGTH))
    }
}

impl<'a> TryWrite<Endian> for MNPayload {
    fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        bytes.write_with(&mut 0, self, endian).unwrap();
        Ok(MN_ENTRY_PAYLOAD_LENGTH)
    }
}
