/*use core::str;
use blake3;
use hashes;
use crate::hashes::Error;
use crate::hashes::Hash as HashTrait;
use crate::hashes::HashEngine as EngineTrait;

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Hash(
    #[cfg_attr(feature = "schemars", schemars(schema_with="crate::util::json_hex_string::len_32"))]
    [u8; 32]
);

hex_fmt_impl!(Debug, Hash);
hex_fmt_impl!(Display, Hash);
hex_fmt_impl!(LowerHex, Hash);
index_impl!(Hash);
serde_impl!(Hash, 32);
borrow_slice_impl!(Hash);

const BLOCK_SIZE: usize = 64;

#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 8],
    length: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            length: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl str::FromStr for Hash {
    type Err = hashes::hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hashes::hex::FromHex::from_hex(s)
    }
}

impl HashTrait for Hash {
    type Engine = HashEngine;
    type Inner = [u8; 32];

    fn engine() -> HashEngine {
        Hash::engine()
    }

    fn from_engine(e: HashEngine) -> Hash {
        //let blake = Hash::from_engine(e);

        let blake = blake3::hash(&e.buffer);

        let mut ret = [0; 32];
        ret.copy_from_slice(blake.as_bytes());
        Hash(ret)
    }

    const LEN: usize = 32;

    fn from_slice(sl: &[u8]) -> Result<Hash, Error> {
        if sl.len() != 32 {
            Err(Error::InvalidLength(Self::LEN, sl.len()))
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Hash(ret))
        }
    }

    const DISPLAY_BACKWARD: bool = true;

    fn into_inner(self) -> Self::Inner {
        self.0
    }

    fn as_inner(&self) -> &Self::Inner {
        &self.0
    }

    fn from_inner(inner: Self::Inner) -> Self {
        Hash(inner)
    }
}

impl hashes::HashEngine for HashEngine {
    type MidState = Midstate;

    #[cfg(not(fuzzing))]
    fn midstate(&self) -> Midstate {
        let mut ret = [0; 32];
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_mut(4)) {
            ret_bytes.copy_from_slice(&u32_to_array_be(*val));
        }
        Midstate(ret)
    }

    #[cfg(fuzzing)]
    fn midstate(&self) -> Midstate {
        let mut ret = [0; 32];
        ret.copy_from_slice(&self.buffer[..32]);
        Midstate(ret)
    }

    const BLOCK_SIZE: usize = 64;

    #[cfg(not(fuzzing))]
    fn input(&mut self, mut inp: &[u8]) {
        while !inp.is_empty() {
            let buf_idx = self.length % <Self as EngineTrait>::BLOCK_SIZE;
            let rem_len = <Self as EngineTrait>::BLOCK_SIZE - buf_idx;
            let write_len = rem_len.min(inp.len());
            self.buffer[buf_idx..buf_idx + write_len].copy_from_slice(&inp[..write_len]);
            self.length += write_len;
            if self.length % <Self as EngineTrait>::BLOCK_SIZE == 0 {
                self.process_block();
            }
            inp = &inp[write_len..];
        }
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }

}
pub fn u32_to_array_be(val: u32) -> [u8; 4] {
    let mut res = [0; 4];
    for i in 0..4 {
        res[i] = ((val >> (4 - i - 1)*8) & 0xff) as u8;
    }
    res
}
*/
