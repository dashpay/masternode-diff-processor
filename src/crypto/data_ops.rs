use std::collections::HashSet;
use std::fmt::{Debug, Formatter, Write};
use byte::BytesExt;
use hashes::{Hash, hash160};
use hashes::hex::ToHex;
use crate::util::base58;

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
    fn script_elements(&self) -> Vec<ScriptElement> { vec![] }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScriptElement<'a> {
    Number(u8),
    Data(&'a [u8], u8)
}


impl<'a> Debug for ScriptElement<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptElement::Number(code) => write!(f, "{:02x}", code)?,
            ScriptElement::Data(data, _) => write!(f, "{}", data.to_hex())?,
        }
        Ok(())
    }
}

impl Data for [u8] {

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, byte::LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, byte::LE).unwrap();
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

impl Data for Vec<u8> {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        (self[(index / 8) as usize] >> (index % 8)) & 1 != 0
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        self.iter().for_each(|bits| {
            let mut bits = bits.clone();
            (0..8).for_each(|_| {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            });
        });
        count
    }

    fn script_elements(&self) -> Vec<ScriptElement> {
        let mut a = Vec::<ScriptElement>::new();
        let len = self.len();
        let mut chunk_size = 0usize;
        let mut i = 0usize;
        'outer: while i < len {
            match self[i] {
                x @ 0 | x @ 0x4f..=0xff => {
                    chunk_size = 1;
                    a.push(ScriptElement::Number(x));
                    i += chunk_size;
                    continue 'outer;
                },
                0x4c => { // OP_PUSHDATA1
                    i += 1;
                    if i + std::mem::size_of::<u8>() > len {
                        break 'outer;
                    }
                    chunk_size = self[i] as usize;
                    i += std::mem::size_of::<u8>();
                },
                0x4d => { // OP_PUSHDATA2
                    i += 1;
                    if i + std::mem::size_of::<u16>() > len {
                        break 'outer;
                    }
                    chunk_size = (self[i] as u16).swap_bytes() as usize;
                    i += std::mem::size_of::<u16>();
                },
                0x4e => { // OP_PUSHDATA4
                    i += 1;
                    if i + std::mem::size_of::<u32>() > len {
                        break 'outer;
                    }
                    chunk_size = (self[i] as u32).swap_bytes() as usize;
                    i += std::mem::size_of::<u32>();
                },
                _ => {
                    chunk_size = self[i] as usize;
                    i += 1;
                }
            };
            if i + chunk_size > len {
                return a;
            }
            let chunk = &self[i..i+chunk_size];
            a.push(ScriptElement::Data(chunk, op_len(chunk)));
            i += chunk_size;
        }
        a
    }

}


pub fn hex_with_data(data: &[u8]) -> String {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let iter = data.iter();
    for a in iter {
        write!(s, "{:02x}", a).unwrap();
    }
    s
}


pub fn short_hex_string_from(data: &[u8]) -> String {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        hex_data[..7].to_string()
    } else {
        hex_data
    }
}


/// Extracts the common values in `a` and `b` into a new set.
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &mut HashSet<T>) -> HashSet<T>
    where
        T: std::hash::Hash,
        T: Eq,
{
    let x: HashSet<(T, bool)> = a
        .drain()
        .map(|v| {
            let intersects = b.contains(&v);
            (v, intersects)
        })
        .collect();
    let mut c = HashSet::new();
    for (v, is_inter) in x {
        if is_inter {
            c.insert(v);
        } else {
            a.insert(v);
        }
    }
    b.retain(|v| !c.contains(v));
    c
}


pub const DASH_PRIVKEY: u8 = 204;
pub const DASH_PRIVKEY_TEST: u8 = 239;
pub const DASH_PUBKEY_ADDRESS: u8 = 76;
pub const DASH_SCRIPT_ADDRESS: u8 = 16;
pub const DASH_PUBKEY_ADDRESS_TEST: u8 = 140;
pub const DASH_SCRIPT_ADDRESS_TEST: u8 = 19;


pub struct ScriptMap {
    // DASH_PRIVKEY | DASH_PRIVKEY_TEST
    pub privkey: u8,
    // DASH_PUBKEY_ADDRESS | DASH_PUBKEY_ADDRESS_TEST
    pub pubkey: u8,
    // DASH_SCRIPT_ADDRESS | DASH_SCRIPT_ADDRESS_TEST
    pub script: u8,
}

impl ScriptMap {
    pub const MAINNET: ScriptMap = ScriptMap {
        privkey: DASH_PRIVKEY,
        pubkey: DASH_PUBKEY_ADDRESS,
        script: DASH_SCRIPT_ADDRESS
    };
    pub const TESTNET: ScriptMap = ScriptMap {
        privkey: DASH_PRIVKEY_TEST,
        pubkey: DASH_PUBKEY_ADDRESS_TEST,
        script: DASH_SCRIPT_ADDRESS_TEST
    };
}
pub fn op_len(data: &[u8]) -> u8 {
    match data.len() {
        // < OP_PUSHDATA1
        0..=0x4d => data.len() as u8,
        // <= u8::MAX,
        0x4e..=0xff => 0x4c,
        // <= u16::MAX
        0x0100..=0xffff => 0x4d,
        //
        _ => 0x4e
    }
}


// NOTE: It's important here to be permissive with scriptSig (spends) and strict with scriptPubKey (receives). If we
// miss a receive transaction, only that transaction's funds are missed, however if we accept a receive transaction that
// we are unable to correctly sign later, then the entire wallet balance after that point would become stuck with the
// current coin selection code
pub fn with_script_pub_key(script: &Vec<u8>, map: &ScriptMap) -> Option<String> {
    match script.script_elements()[..] {
        // pay-to-pubkey-hash scriptPubKey
        [ScriptElement::Number(0x76/*OP_DUP*/), ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x88/*OP_EQUALVERIFY*/), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
            Some([&[map.pubkey], data].concat()),
        // pay-to-script-hash scriptPubKey
        [ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x87/*OP_EQUAL*/)] =>
            Some([&[map.script], data].concat()),
        // pay-to-pubkey scriptPubKey
        [ScriptElement::Data(data, len @ 33u8 | len @ 65u8), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
            Some([&[map.pubkey] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
        // unknown script type
        _ => None
    }.and_then(|data| Some(base58::check_encode_slice(&data)))
}

pub fn with_script_sig(script: &Vec<u8>, map: &ScriptMap) -> Option<String> {
    match script.script_elements()[..] {
        // pay-to-pubkey-hash scriptSig
        [.., ScriptElement::Data(.., 0..=0x4e), ScriptElement::Data(data, len @ 33 | len @ 65)] =>
            Some([&[map.pubkey] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
        // pay-to-script-hash scriptSig
        [.., ScriptElement::Data(.., 0..=0x4e), ScriptElement::Data(data, len @ 0..=0x4e)] =>
            Some([&[map.script] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
        // pay-to-pubkey scriptSig
        // TODO: implement Peter Wullie's pubKey recovery from signature
        [.., ScriptElement::Data(.., 0..=0x4e)] => None,
        // unknown script type
        _ => None
    }.and_then(|data| Some(base58::check_encode_slice(&data)))

}
