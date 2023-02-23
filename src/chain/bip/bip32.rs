use byte::BytesExt;
use hashes::{Hash, sha256d};
use crate::chain::common::ChainType;
use crate::consensus::Encodable;
use crate::crypto::byte_util::clone_into_array;
use crate::crypto::UInt256;
use crate::derivation::BIP32_HARD;
use crate::util::{base58, endian};

#[allow(unused_assignments)]

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Error {
    /// Invalid character encountered
    BadBase58(base58::Error),
    /// Checksum was not correct (expected, actual)
    BadChecksum(u32, u32),
    /// Checksum was not correct (expected, actual)
    InvalidAddress([u8; 4]),

    /// The length (in bytes) of the object was not correct
    /// Note that if the length is excessively long the provided length may be
    /// an estimate (and the checksum step may be skipped).
    InvalidLength(usize),
    /// Extended Key version byte(s) were not recognized
    InvalidExtendedKeyVersion([u8; 4]),
    /// Address version byte were not recognized
    InvalidAddressVersion(u8),
    /// Checked data was less than 4 bytes
    TooShort(usize),
}

impl From<base58::Error> for Error {
    fn from(value: base58::Error) -> Self {
        Error::BadBase58(value)
    }
}

pub struct Key {
    pub depth: u8,
    pub fingerprint: u32,
    pub child: UInt256,
    pub chain: UInt256,
    pub data: Vec<u8>,
    pub hardened: bool
}

impl Key {
    pub fn new(depth: u8, fingerprint: u32, child: UInt256, chain: UInt256, data: Vec<u8>, hardened: bool) -> Self {
        Self {
            depth,
            fingerprint,
            child,
            chain,
            data,
            hardened
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.fingerprint.enc(&mut writer);
        self.chain.enc(&mut writer);
        writer.extend_from_slice(&self.data);
        writer
    }
}

//
// impl<'a> TryRead<'a, &Params> for Key<u32> {
//     fn try_read(bytes: &'a [u8], ctx: &Params) -> byte::Result<(Self, usize)> {
//         let mut offset = 0;
//         let depth = bytes.read_with::<u8>(&mut offset, byte::LE).unwrap();
//         let fingerprint = bytes.read_with::<u32>(&mut offset, byte::LE).unwrap();
//         let child_32 = bytes.read_with::<u32>(&mut offset, byte::BE).unwrap();
//         let chain = bytes.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
//         if bytes.eq(&ctx.bip32_script_map.xprv) {
//             *offset += 1;
//         }
//         let hardened = (child_32 & BIP32_HARD) > 0;
//         let child = UInt256::from(child_32 & !BIP32_HARD);
//         let d: &[u8] = bytes.read_with(&mut offset, Bytes::Len(bytes.len() - *offset)).unwrap();
//         Ok((Self { depth, fingerprint, child, chain, data: d.to_vec(), hardened }, *offset))
//     }
// }
//
// impl<'a> TryRead<'a, &Params> for Key<UInt256> {
//     fn try_read(bytes: &'a [u8], ctx: &Params) -> byte::Result<(Self, usize)> {
//         let mut offset = 0;
//         let depth = bytes.read_with::<u8>(&mut offset, byte::LE).unwrap();
//         let fingerprint = bytes.read_with::<u32>(&mut offset, byte::LE).unwrap();
//         // todo: check: *hardened = [data BOOLAtOffset:offset];
//         let hardened = bytes.read_with::<u8>(&mut offset, byte::LE).unwrap() >= 0;
//         let child = bytes.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
//         let chain = bytes.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
//         if bytes.eq(if ctx.chain_type == ChainType::MainNet { ctx.dip14_script_map.dps } else { ctx.bip32_script_map.xprv }) {
//             *offset += 1;
//         }
//         let d: &[u8] = bytes.read_with(&mut offset, Bytes::Len(bytes.len() - *offset)).unwrap();
//         Ok((Self { depth, fingerprint, child, chain, data: d.to_vec(), hardened }, *offset))
//     }
// }

impl Key {
    pub fn serialize(&self, chain_type: ChainType) -> String {
        if self.child.is_31_bits() {
            let mut child = u32::from_le_bytes(clone_into_array(&self.child.0[..4]));
            if self.hardened {
                child |= BIP32_HARD;
            }
            child = child.swap_bytes();
            // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)])
            let mut writer = Vec::<u8>::with_capacity(14 + self.data.len() + std::mem::size_of::<UInt256>());
            let is_priv = self.data.len() < 33;
            writer.extend_from_slice(&if is_priv { chain_type.bip32_script_map().xprv } else { chain_type.bip32_script_map().xpub }); // 4
            self.depth.enc(&mut writer);             // 5
            self.fingerprint.enc(&mut writer);       // 9
            child.enc(&mut writer);             // 13
            self.chain.enc(&mut writer);             // 45
            if is_priv {
                b'\0'.enc(&mut writer);              // 46 (prv) / 45 (pub)
            }
            writer.extend_from_slice(self.data.as_slice()); // 78 (prv) / 78 (pub)
            base58::check_encode_slice(&writer)
        } else {
            // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:47 + key.length + sizeof(chain)])
            let mut writer = Vec::<u8>::with_capacity(47 + self.data.len() + std::mem::size_of::<UInt256>());
            let is_priv = self.data.len() < 33;
            writer.extend_from_slice(&if is_priv { chain_type.dip14_script_map().dps } else { chain_type.dip14_script_map().dpp }); // 4
            self.depth.enc(&mut writer);             // 5
            self.fingerprint.enc(&mut writer);       // 9
            self.hardened.enc(&mut writer);          // 10
            self.child.enc(&mut writer);             // 42
            self.chain.enc(&mut writer);             // 74
            if is_priv {
                b'\0'.enc(&mut writer);              // 75 (prv) / 74 (pub)
            }
            writer.extend_from_slice(self.data.as_slice()); // 107 (prv) / 107 (pub)
            base58::check_encode_slice(&writer)
        }

    }
}

fn split_msg(message: Vec<u8>, mid: usize) -> (Vec<u8>, Vec<u8>) {
    let (data, checked_data) = message.split_at(mid);
    (data.to_vec(), checked_data.to_vec())
}

fn from_message(message: Vec<u8>, chain_type: ChainType) -> Result<Key, Error> {
    let len = message.len();
    let mid = len - 4;
    let (data, checked_data) = split_msg(message, len - 4);
    let (head, tail) = split_msg(data.clone(), 4);
    let expected = endian::slice_to_u32_le(&sha256d::Hash::hash(&data)[..4]);
    let actual = endian::slice_to_u32_le(&checked_data);
    let header: [u8; 4] = clone_into_array(&head);
    let mut offset = &mut 4;
    match (expected == actual, len) {
        (true, 82) => {
            // 32
            // todo: maybe we need to check testnet script map too
            if chain_type.bip32_script_map().xpub.ne(&header) &&
                chain_type.bip32_script_map().xprv.ne(&header) {
                return Err(Error::InvalidAddress(header));
            }
            // if !data.eq(params.bip32_script_map.xpub) &&
            //     !data.eq(params.bip32_script_map.xprv) {
            //     return Err(Error::InvalidAddress(data));
            // }
            // let depth = all_data[5];
            // let fingerprint = u32::from_le_bytes(clone_into_array(&all_data[6..10]));
            // let chain = UInt256::from(&all_data[10..42]);
            // let child_32 = u32::from_le_bytes(clone_into_array(&all_data[42..46]));
            // if params.bip32_script_map.xprv.eq(&all_data[..4]) {
            //
            // }
            let depth = data.read_with::<u8>(&mut offset, byte::LE).unwrap();
            let fingerprint = data.read_with::<u32>(&mut offset, byte::LE).unwrap();
            let child_32 = data.read_with::<u32>(&mut offset, byte::BE).unwrap();
            let chain = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
            if chain_type.bip32_script_map().xprv.eq(&header) {
                *offset += 1;
            }
            let hardened = (child_32 & BIP32_HARD) > 0;
            let child = UInt256::from(child_32 & !BIP32_HARD);
            let d = Vec::<u8>::from(&data[*offset..]);
            Ok(Key { depth, fingerprint, child, chain, data: d, hardened })
        },
        (true, 111) => {
            // 256
            // todo: maybe we need to check testnet script map too
            if chain_type.dip14_script_map().dps.ne(&header) && chain_type.dip14_script_map().dpp.ne(&header) {
                return Err(Error::InvalidAddress(header));
            }
            // if !data.eq(params.dip14_script_map.dps) &&
            //     !data.eq(params.dip14_script_map.dpp) {
            //     return Err(Error::InvalidAddress(data));
            // }
            let depth = data.read_with::<u8>(&mut offset, byte::LE).unwrap();
            let fingerprint = data.read_with::<u32>(&mut offset, byte::LE).unwrap();
            // todo: check: *hardened = [data BOOLAtOffset:offset];
            let hardened = data.read_with::<u8>(&mut offset, byte::LE).unwrap() >= 0;
            let child = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
            let chain = data.read_with::<UInt256>(&mut offset, byte::LE).unwrap();
            if data.eq(&if chain_type == ChainType::MainNet { chain_type.dip14_script_map().dps } else { chain_type.bip32_script_map().xprv }) {
                *offset += 1;
            }
            let mut d = Vec::<u8>::new();
            d.extend_from_slice(&data[*offset..]);
            // let d: &[u8] = data.read_with(&mut offset, Bytes::Len(data.len() - *offset)).unwrap();
            Ok(Key { depth, fingerprint, child, chain, data: d, hardened })
        },
        (true, _) => Err(Error::InvalidLength(len)),
        _ => Err(Error::BadChecksum(expected, actual)),
    }

    // let (data, checked_data) = all_data.split_at(len_4);
    // let data = unsafe { slice::from_raw_parts(all_data.as_mut_ptr(), len_4) };
    // let checked_data = unsafe { slice::from_raw_parts(all_data[len_4..].as_mut_ptr(), *offset) };
    // let data = &all_data[..len_4];
    // let checked_data = &all_data[len_4..];
    // let hashed = UInt256::sha256d(data);
    // let hashed_data = hashed.0[..4];
    // let hashed_data: [u8; 4] = clone_into_array(&hashed.0[..4]);

    // let hashed_data = &UInt256::sha256d(data).0[..*offset];
    // if expected != actual {
    //     Err(Error::BadChecksum(expected, actual))
    // } else {
    //     match len {
    //         82 => {
    //
    //         },
    //         111 => {
    //
    //         },
    //         _ => Err(Error::InvalidLength(all_data.len()))
    //     }
    // }

}

// Decode base58-encoded string into bip32 private key
pub fn from(data: &String, chain_type: ChainType) -> Result<Key, Error> {
    base58::from(data.as_str())
        .map_err(base58::Error::into)
        .and_then(|message| from_message(message, chain_type))
}

pub mod StringKey {
    use byte::BytesExt;
    use crate::chain::common::ChainType;
    use crate::consensus::Encodable;
    use crate::crypto::byte_util::clone_into_array;
    use crate::crypto::UInt256;
    use crate::derivation::BIP32_HARD;
    use crate::util::base58;

    // helper function for serializing BIP32 master public/private keys to standard export format
    fn deserialize(data: &str, mut depth: u8, mut fingerprint: u32, mut hardened: bool, mut child: UInt256, mut chain: UInt256, chain_type: ChainType) -> Option<Vec<u8>> {
        match base58::from(data) {
            Ok(all_data) if all_data.len() == 82 => {
                let mut child_32 = 0u32;
                match deserialize_32(data, depth, fingerprint, child_32, chain, chain_type) {
                    Some(key) => {
                        child_32 = child_32.swap_bytes();
                        hardened = (child_32 & BIP32_HARD) > 0;
                        child = UInt256::from(child_32 & !BIP32_HARD);
                        return Some(key);
                    },
                    None => None
                }
            }
            Ok(all_data) if all_data.len() == 111 => deserialize_256(data, depth, fingerprint, hardened, child, chain, chain_type),
            _ => None
        }
    }
    // helper function for serializing BIP32 master public/private keys to standard export format
    fn deserialize_32(data: &str, mut depth: u8, mut fingerprint: u32, mut child: u32, mut chain: UInt256, chain_type: ChainType) -> Option<Vec<u8>> {
        match base58::from(data) {
            Ok(all_data) if all_data.len() == 82 => {
                let len_4 = all_data.len() - 4;
                let data = &all_data[..len_4];
                let checked_data = &all_data[len_4..];
                let hashed_data = &UInt256::sha256d(&data).0[..4];
                if !hashed_data.eq(checked_data) {
                    return None;
                }
                // todo: maybe we need to check testnet script map too
                if chain_type.bip32_script_map().xpub.ne(data) && chain_type.bip32_script_map().xprv.ne(data) {
                    return None;
                }
                // if !data.eq(params.bip32_script_map.xpub) &&
                //     !data.eq(params.bip32_script_map.xprv) {
                //     return None;
                // }
                let mut offset = &mut 4;
                depth = data.read_with::<u8>(offset, byte::LE).unwrap();
                fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                child = data.read_with::<u32>(offset, byte::LE).unwrap();
                chain = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                if chain_type.bip32_script_map().xprv.eq(data) {
                    *offset += 1;
                }
                // if data.eq(params.bip32_script_map.xprv) {
                //     *offset += 1;
                // }
                Some(data[*offset..data.len()].to_vec())
            },
            _ => None
        }
    }
    // helper function for serializing BIP32 master public/private keys to standard export format
    fn deserialize_256(data: &str, mut depth: u8, mut fingerprint: u32, mut hardened: bool, mut child: UInt256, mut chain: UInt256, chain_type: ChainType) -> Option<Vec<u8>> {
        match base58::from(data) {
            Ok(all_data) if all_data.len() == 111 => {
                let len_4 = all_data.len() - 4;
                let data = &all_data[..len_4];
                let checked_data = &all_data[len_4..];
                let hashed_data = &UInt256::sha256d(data).0[..4];
                if !hashed_data.eq(checked_data) {
                    return None;
                }
                // todo: maybe we need to check testnet script map too
                if chain_type.dip14_script_map().dps.ne(data) && chain_type.dip14_script_map().dpp.ne(data) {
                    return None;
                }

                // if !data.eq(params.dip14_script_map.dps) &&
                //     !data.eq(params.dip14_script_map.dpp) {
                //     return None;
                // }
                let mut offset = &mut 4;
                depth = data.read_with::<u8>(offset, byte::LE).unwrap();
                fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                // todo: check: *hardened = [data BOOLAtOffset:offset];
                hardened = data.read_with::<u8>(offset, byte::LE).unwrap() >= 0;
                child = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                chain = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                if if chain_type.is_mainnet() { chain_type.dip14_script_map().dps } else { chain_type.bip32_script_map().xprv }.eq(data) {
                    *offset += 1;
                }
                Some(data[*offset..data.len()].to_vec())
            },
            _ => None
        }
    }

    // helper function for serializing BIP32 master public/private keys to standard export format
    pub(crate) fn serialize(depth: u8, fingerprint: u32, hardened: bool, child: UInt256, chain: UInt256, key: Vec<u8>, chain_type: ChainType) -> String {
        if child.is_31_bits() {
            let mut small_i = u32::from_le_bytes(clone_into_array(&child.0[..4]));
            if hardened {
                small_i |= BIP32_HARD;
            }
            small_i = small_i.swap_bytes();
            serialize_32(depth, fingerprint, small_i, chain, key, chain_type)
        } else {
            serialize_256(depth, fingerprint, hardened, child, chain, key, chain_type)
        }
    }

    // helper function for serializing BIP32 master public/private keys to standard export format
    fn serialize_32(depth: u8, fingerprint: u32, child: u32, chain: UInt256, key: Vec<u8>, chain_type: ChainType) -> String {
        // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)])
        let mut writer = Vec::<u8>::with_capacity(14 + key.len() + std::mem::size_of::<UInt256>());
        let is_priv = key.len() < 33;
        writer.extend_from_slice(&if is_priv { chain_type.bip32_script_map().xprv } else { chain_type.bip32_script_map().xpub }); // 4
        depth.enc(&mut writer);             // 5
        fingerprint.enc(&mut writer);       // 9
        child.enc(&mut writer);             // 13
        chain.enc(&mut writer);             // 45
        if is_priv {
            b'\0'.enc(&mut writer);         // 46 (prv) / 45 (pub)
        }
        writer.extend(key);            // 78 (prv) / 78 (pub)
        base58::check_encode_slice(&writer)
    }

    // helper function for serializing BIP32 master public/private keys to standard export format
    fn serialize_256(depth: u8, fingerprint: u32, hardened: bool, child: UInt256, chain: UInt256, key: Vec<u8>, chain_type: ChainType) -> String {
        // TODO: SecAlloc ([NSMutableData secureDataWithCapacity:47 + key.length + sizeof(chain)])
        let mut writer = Vec::<u8>::with_capacity(47 + key.len() + std::mem::size_of::<UInt256>());
        let is_priv = key.len() < 33;
        writer.extend_from_slice(&if is_priv { chain_type.dip14_script_map().dps } else { chain_type.dip14_script_map().dpp }); // 4
        depth.enc(&mut writer);             // 5
        fingerprint.enc(&mut writer);       // 9
        hardened.enc(&mut writer);          // 10
        child.enc(&mut writer);             // 42
        chain.enc(&mut writer);             // 74
        if is_priv {
            b'\0'.enc(&mut writer);         // 75 (prv) / 74 (pub)
        }
        writer.extend(key); // 107 (prv) / 107 (pub)
        base58::check_encode_slice(&writer)
    }
}
