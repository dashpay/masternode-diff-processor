use byte::{BytesExt, check_len, LE, Result, TryRead, TryWrite};
use byte::ctx::{Bytes, Endian};
use std::fmt::Write;
use std::{mem, slice};
use crate::{CoinbaseTransaction, MasternodeEntry, LLMQEntry};
use crate::consensus::{Decodable, Encodable, ReadExt, WriteExt};
use crate::consensus::encode::VarInt;
use crate::hashes::{Hash, sha256d, hex::{FromHex, ToHex}, hex};
use crate::transactions::transaction::{Transaction, TransactionInput, TransactionOutput};

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
}

impl Data for [u8] {

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
pub fn data_at_offset_from<'a>(buffer: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let var_int: VarInt = VarInt::from_bytes(buffer, offset)?;
    match buffer.read_with(offset, Bytes::Len(var_int.0 as usize)) {
        Ok(data) => Some(data),
        Err(error) => None
    }
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

pub trait Zeroable {
    fn is_zero(&self) -> bool;
}

pub trait ConstDecodable<'a, T: TryRead<'a, Endian>> {
    fn from_const(bytes: *const u8) -> Option<T>;
}
pub trait BytesDecodable<'a, T: TryRead<'a, Endian>> {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<T>;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt128(pub [u8; 16]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt160(pub [u8; 20]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt256(pub [u8; 32]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt384(pub [u8; 48]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt512(pub [u8; 64]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt768(pub [u8; 96]);

macro_rules! impl_bytes_decodable {
    ($var_type: ident) => {
        impl<'a> BytesDecodable<'a, $var_type> for $var_type {
            fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
                match bytes.read_with(offset, LE) {
                    Ok(data) => Some(data),
                    Err(_err) => None
                }
            }
        }
    }
}
macro_rules! impl_bytes_decodable_lt {
    ($var_type: ident) => {
        impl<'a> BytesDecodable<'a, $var_type<'a>> for $var_type<'a> {
            fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
                match bytes.read_with(offset, LE) {
                    Ok(data) => Some(data),
                    Err(_err) => None
                }
            }
        }
    }
}

macro_rules! impl_decodable {
    ($var_type: ident, $byte_len: expr) => {
        impl_bytes_decodable!($var_type);

        impl<'a> ConstDecodable<'a, $var_type> for $var_type {
            fn from_const(bytes: *const u8) -> Option<Self> {
                let safe_bytes = unsafe { slice::from_raw_parts(bytes, $byte_len) };
                match safe_bytes.read_with::<Self>(&mut 0, LE) {
                    Ok(data) => Some(data),
                    Err(_err) => None
                }
            }
        }
    }
}

macro_rules! define_try_read_to_big_uint {
    ($uint_type: ident, $byte_len: expr) => {
        impl<'a> TryRead<'a, Endian> for $uint_type {
            fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
                let offset = &mut 0;
                let mut data: [u8; $byte_len] = [0u8; $byte_len];
                for _i in 0..$byte_len {
                    let index = offset.clone();
                    let chunk = bytes.read_with::<u8>(offset, endian)?;
                    data[index] = chunk;
                }
                Ok(($uint_type(data), $byte_len))
            }
        }
    }
}

macro_rules! define_bytes_to_big_uint {
    ($uint_type: ident, $byte_len: expr) => {
        define_try_read_to_big_uint!($uint_type, $byte_len);
        impl std::default::Default for $uint_type {
            fn default() -> Self {
                let mut data: [u8; $byte_len] = [0u8; $byte_len];
                for i in 0..$byte_len {
                    data[i] = 0;
                }
                Self(data)
            }
        }

        impl std::fmt::Display for $uint_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.0.to_hex())?;
                Ok(())
            }
        }
        impl std::fmt::Debug for $uint_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                // for i in 0..self.len() {
                    write!(f, "{}", self.0.to_hex())?;
                // }
                Ok(())
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
            fn consensus_decode<D: std::io::Read>(mut d: D) -> std::result::Result<Self, crate::consensus::encode::Error> {
                let mut ret = [0; $byte_len];
                d.read_slice(&mut ret)?;
                Ok($uint_type(ret))
            }
        }

        impl Reversable for $uint_type {
            fn reversed(&mut self) -> Self {
                self.0.reverse();
                *self
            }
        }
        impl FromHex for $uint_type {
            fn from_byte_iter<I>(iter: I) -> std::result::Result<Self, hex::Error>
                where I: Iterator<Item=std::result::Result<u8, hashes::hex::Error>> +
                ExactSizeIterator +
                DoubleEndedIterator {
                if iter.len() == $byte_len {
                    let mut ret = [0; $byte_len];
                    for (n, byte) in iter.enumerate() {
                        ret[n] = byte?;
                    }
                    Ok($uint_type(ret))
                } else {
                    Err(hex::Error::InvalidLength(2 * $byte_len, 2 * iter.len()))
                }
            }
        }

        impl Zeroable for $uint_type {
            fn is_zero(&self) -> bool {
                for i in 0..$byte_len {
                    if self.0[i] == 1 {
                        return true;
                    }
                }
                false
            }
        }
        impl_decodable!($uint_type, $byte_len);
    }
}

impl_decodable!(u8, 1);
impl_decodable!(u16, 2);
impl_decodable!(u32, 4);
impl_decodable!(u64, 8);
impl_decodable!(usize, mem::size_of::<usize>());
impl_decodable!(i8, 1);
impl_decodable!(i16, 2);
impl_decodable!(i32, 4);
impl_decodable!(i64, 8);
impl_decodable!(isize, mem::size_of::<isize>());


define_bytes_to_big_uint!(UInt128, 16);
define_bytes_to_big_uint!(UInt160, 20);
define_bytes_to_big_uint!(UInt256, 32);
define_bytes_to_big_uint!(UInt384, 48);
define_bytes_to_big_uint!(UInt512, 64);
define_bytes_to_big_uint!(UInt768, 96);

impl<'a> TryRead<'a, Endian> for VarInt {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        match VarInt::consensus_decode(bytes) {
            Ok(data) => Ok((data, data.len())),
            Err(err) => Err(byte::Error::BadInput { err: "Error: VarInt" })
        }
    }
}

impl_bytes_decodable!(VarInt);
impl_bytes_decodable!(MasternodeEntry);

impl_bytes_decodable_lt!(TransactionInput);
impl_bytes_decodable_lt!(TransactionOutput);
impl_bytes_decodable_lt!(Transaction);
impl_bytes_decodable_lt!(CoinbaseTransaction);
impl_bytes_decodable_lt!(LLMQEntry);

/// A variable-length bytes
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct VarBytes<'a>(pub VarInt, pub &'a [u8]);

impl<'a> TryRead<'a, Endian> for VarBytes<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;
        let var_int = match VarInt::consensus_decode(bytes) {
            Ok(data) => data,
            Err(err) => { return Err(byte::Error::BadInput {err: "Error: VarInt::try_read"}); }
        };
        *offset += var_int.len();
        let payload_length = var_int.0 as usize;
        let var_bytes = VarBytes(var_int, bytes.read_with(offset, Bytes::Len(payload_length))?);
        Ok((var_bytes, payload_length))
    }
}
impl<'a> BytesDecodable<'a, VarBytes<'a>> for VarBytes<'a> {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
        let var_int: VarInt = VarInt::from_bytes(bytes, offset)?;
        match bytes.read_with(offset, Bytes::Len(var_int.0 as usize)) {
            Ok(data) => Some(VarBytes(var_int, data)),
            Err(_err) => None
        }
    }
}
