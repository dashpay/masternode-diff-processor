use hashes::Hash;
use std::fmt::Write;
use crate::consensus::Encodable;
use crate::crypto::UInt256;

pub const DASH_MESSAGE_MAGIC: &str = "DarkCoin Signed Message:\n";

#[inline]
pub fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    use secp256k1::rand;
    use secp256k1::rand::distributions::Uniform;
    use secp256k1::rand::Rng;
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, 255);
    (0..size).map(|_| rng.sample(&range)).collect()
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

#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<UInt256>) -> Option<UInt256> {
    let length = hashes.len();
    let mut level = hashes.clone();
    if length == 0 { return None; }
    if length == 1 { return Some(hashes[0]); }
    while level.len() != 1 {
        let len = level.len();
        let capacity = (0.5 * len as f64).round();
        let mut higher_level: Vec<UInt256> = Vec::with_capacity(capacity as usize);
        for i in (0..len).step_by(2) {
            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            let left = level[i];
            left.enc(&mut buffer);
            if len > i + 1 { level[i+1] } else { left }.enc(&mut buffer);
            higher_level.push(UInt256(hashes::sha256d::Hash::hash(&buffer).into_inner()));
        }
        level = higher_level;
    }
    Some(level[0])
}
