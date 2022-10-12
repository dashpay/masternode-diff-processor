pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;

#[cfg(feature = "std")]
use std::io;
#[cfg(not(feature = "std"))]
use core2::io;

#[macro_use]
pub mod internal_macros;

pub mod blockdata;
pub mod consensus;
pub mod crypto;
pub mod hash_types;
pub mod network;
pub mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
