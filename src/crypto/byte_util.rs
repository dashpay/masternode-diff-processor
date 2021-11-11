use byte::{BytesExt, check_len, LE, Result, TryRead, TryWrite};
use byte::ctx::{Bytes, Endian};
use std::fmt::Write;
use crate::consensus::{Decodable, Encodable, ReadExt, WriteExt};
use crate::consensus::encode::{Error, VarInt};
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


pub fn hex_with_data(data: &[u8]) -> String {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let mut iter = data.iter();
    while let Some(a) = iter.next() {
        write!(s, "{:02X}", a).unwrap();
    }
    s
}

#[inline]
pub fn data_at_offset_from<'a>(buffer: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let var_int: VarInt = match VarInt::consensus_decode(&buffer[*offset..]) {
        Ok(data) => data,
        Err(_error) => {
            return byte::Result::Err(byte::Error::Incomplete);
        }
    };
    let var_int_value = var_int.0 as usize;
    let var_int_length = var_int.len();
    *offset += var_int_length;
    let data: &[u8] = match buffer.read_with(offset, Bytes::Len(var_int_value)) {
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
    while level.len() != 1 {
        for i in (0..level.len()).step_by(2) {
            let left = level[i];
            let offset = &mut 0;
            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            *offset += left.consensus_encode(&mut buffer).unwrap();
            *offset +=
                if level.len() - i > 1 {
                    level[i+1]
                } else {
                    left
                }.consensus_encode(&mut buffer).unwrap();

            higher_level.push(UInt256(sha256d::Hash::hash(&buffer).into_inner()));
        }
        level = higher_level.clone();
        higher_level.clear();
    }
    return Some(level[0]);
}

pub fn short_hex_string_from(data: &[u8]) -> String {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        hex_data[..7].to_string()
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
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct UInt256(pub [u8; 32]);
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt384(pub [u8; 48]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UInt768(pub [u8; 96]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MNPayload(pub [u8; MN_ENTRY_PAYLOAD_LENGTH]);

macro_rules! define_bytes_to_big_uint {
    ($uint_type: ident, $byte_len: expr) => {
        impl<'a> TryRead<'a, Endian> for $uint_type {
            fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
                let offset = &mut 0;
                let mut data: [u8; $byte_len] = [0u8; $byte_len];
                for _i in 0..$byte_len {
                    let index = offset.clone();
                    let chunk = match bytes.read_with::<u8>(offset, endian) {
                        Ok(data) => data,
                        Err(_err) => { return Err(_err); }
                    };
                    data[index] = chunk;
                }
                Ok(($uint_type(data), $byte_len))
            }
        }
        // impl<'a> TryWrite<Endian> for $uint_type {
        //     fn try_write(self, bytes: &mut [u8], endian: Endian) -> Result<usize> {
        //         match bytes.write_with(&mut 0, self, endian) {
        //             Ok(_data) => Ok($byte_len),
        //             Err(_err) => Err(_err)
        //         }
        //     }
        // }
        impl std::fmt::Display for $uint_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                for ch in &self.0 {
                    write!(f, "{:02x}", ch)?;
                }
                Ok(())
            }
        }
        impl Reversable for $uint_type {
            fn reversed(&mut self) -> Self {
                self.0.reverse();
                *self
            }
        }
        impl Encodable for $uint_type {
            #[inline]
            fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> std::result::Result<usize, std::io::Error> {
                writer.emit_slice(&self.0[..])?;
                Ok($byte_len)
            }
        }

        impl Decodable for $uint_type {
            #[inline]
            fn consensus_decode<D: std::io::Read>(mut d: D) -> std::result::Result<Self, Error> {
                let mut ret = [0; $byte_len];
                d.read_slice(&mut ret)?;
                Ok($uint_type(ret))
            }
        }
    }
}

define_bytes_to_big_uint!(UInt128, 16);
define_bytes_to_big_uint!(UInt160, 20);
define_bytes_to_big_uint!(UInt256, 32);
define_bytes_to_big_uint!(UInt384, 48);
define_bytes_to_big_uint!(UInt768, 96);
define_bytes_to_big_uint!(MNPayload, MN_ENTRY_PAYLOAD_LENGTH);
