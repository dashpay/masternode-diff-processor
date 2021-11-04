use std::fmt;
use std::fmt::{Display, Formatter, Result};
use std::hash::Hasher;
use std::io::Write;
use byte::{BytesExt, LE};
use secrets::Secret;
use secrets::traits::AsContiguousBytes;
use crate::chain::chain::Chain;
use crate::crypto::{DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST};
use crate::crypto::data_ops::{sha256_1, sha256_2};
use crate::util::base58::{c, encode_slice};

pub trait Data {
    // fn address_from_hash_160_data_for_chain(&self, chain: Chain) -> &str;
    fn base_58_check(&self) -> &str;
    fn base_58_string(&self) -> &str;
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
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
    }*/

    fn base_58_check(&self) -> &str {
        const LENGTH: usize = self.len() + 4;
        Secret::<[u8; LENGTH]>::random(|mut buf | {
            let offset: &mut usize = &mut 0;
            buf.write(offset, &self);
            buf.write(offset, sha256_2(&buf) as u32);
            buf.base_58_string()
        })
    }

    fn base_58_string(&self) -> &str {
        &encode_slice(&self)
    }

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, LE) {
            Some(bits) => (bits >> bit_position) & 1
        }
    }



    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for &mut i in 0..self.len() {
            let bits = self.read_with(i, LE)?;
            for _j in 0..8 {
                if bits & 1 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
        // for (uint64_t i = 0; i < self.length; i++) {
        //     uint8_t bits = [self UInt8AtOffset:i];
        //     for (uint8_t j = 0; j < 8; j++) {
        //         if (bits & 1) trueBitsCount++;
        //         bits >>= 1;
        //     }
        // }
        // return trueBitsCount;
    }

}


pub fn hex_with_data(data: &[u8]) -> &str {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let mut iter = data.iter();
    while let Some(a) = iter.next() {
        write!(s, "{:02X}", a)?;
    }
    &s
}

pub fn merkle_root_from_hashes(hashes: Vec<[u8; 32]> ) -> Option<[u8; 32]> {
    let length = hashes.len();
    let mut level = hashes.clone();
    if length == 0 { return None; }
    if length == 1 { return Some(hashes[0]); }
    let mut higher_level: Vec<[u8; 32]> = vec![];
    while hashes.len() != 1 {
        for i in (0..level.len()).step_by(2) {
            let left = level[i];
            let mut combined: Vec<[u8; 32]> = vec![left];
            if level.len() - i > 1 {
                combined.push(level[i + 1]);
            } else {
                combined.push(left);
            }
            higher_level.push(sha256_2(combined.as_bytes()));
        }
        level = higher_level.clone();
        higher_level.clear();
    }
    return Some(level[0]);
}

/*
+ (NSData *)merkle_root_from_hashes:(NSArray *)hashes {
    NSMutableArray *higherLevel = [NSMutableArray array];
    NSArray *level = hashes;
    if (hashes.count == 1) return hashes[0];
    if (hashes.count == 0) return nil;
    while (level.count != 1) {
        for (int i = 0; i < level.count; i += 2) {
            if ([level count] - i > 1) {
                NSData *left = level[i + 0];
                NSData *right = level[i + 1];
                NSMutableData *combined = [NSMutableData data];
                [combined appendData:left];
                [combined appendData:right];
                [higherLevel addObject:[NSData dataWithUInt256:combined.SHA256_2]];
            } else {
                NSData *left = level[i];
                NSMutableData *combined = [NSMutableData data];
                [combined appendData:left];
                [combined appendData:left];
                [higherLevel addObject:[NSData dataWithUInt256:combined.SHA256_2]];
            }
        }
        level = [higherLevel copy];
        higherLevel = [NSMutableArray array];
    }
    return level[0];
}
*/

pub fn short_hex_string_from(data: &[u8]) -> &str {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        &hex_data[..7]
    } else {
        hex_data
    }
}

/*pub fn var_int(off: &mut usize) -> (u64, u32) {
    let header = message.read_with::<u8>(off, LE)?;
    let mut length: u32 = 1;
    let result = match header {
        0xfd => {
            length += 2;
            message.read_with::<u16>(off, LE)?
        },
        0xfe => {
            length += 4;
            message.read_with::<u32>(off, LE)?
        },
        0xff => {
            length += 8;
            message.read_with::<u64>(off, LE)?
        },
        _ => header
    };
    (result, length)
}

pub fn append_var_int(data: &mut [u8], i: u64) {
    // 0..=0xFC             => { 1 }
    // 0xFD..=0xFFFF        => { 3 }
    // 0x10000..=0xFFFFFFFF => { 5 }
    // _                    => { 9 }
    match i {
        0..0xfc => {
            data.write_u8(i as u8);
        },
        0xfd..0xffff => {
            data.write_u8(0xfd);
            data.write_u16(i as u16);
        }
        0x10000..0xffffffff => {
            data.write_u8(0xfe);
            data.write_u32(i as u32);
        }
        _ => {
            data.write_u8(0xff);
            data.write_u64(i as u64);
        }
    }
}

pub fn var_int_from(i: u64) -> &[u8] {
    let data = &mut [0u8; 1];

    match i {
        0..0xfc => {
            data.write_u8(i as u8);
        },
        0xfd..0xffff => {
            data.write_u8(0xfd);
            data.write_u16(i as u16);
        }
        0x10000..0xffffffff => {
            data.write_u8(0xfe);
            data.write_u32(i as u32);
        }
        _ => {
            data.write_u8(0xff);
            data.write_u64(i as u64);
        }
    }
    return data;

}*/
