// use byte::BytesExt;
// use secrets::Secret;
// use hashes::{Hash, hash160};
// use crate::crypto::{DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST};
// use crate::crypto::byte_util::Data;

use crate::crypto::byte_util::UInt160;

// #[repr(C)]
#[derive(Debug)]
pub enum KeyType {
    ECDSA = 0,
    BLS = 1,
}

// #[repr(C)]
#[derive(Debug)]
pub struct Key<'a> {
    pub extended_public_key_data: &'a [u8],
    pub extended_private_key_data: &'a [u8],
    pub public_key_data: &'a [u8],
    pub private_key_data: &'a [u8],
    pub hash160: UInt160,
    pub secret_key_string: &'a str,
    pub key_type: KeyType,
    pub localized_key_type: &'a str,
}

/*impl Key {
    pub fn addressWithPublicKeyData(data: &[u8], chain: Chain) -> &str {
        Secret::<[u8; 21]>::random(|mut s| {
            const BUFFER_LENGTH: usize = 1 + 20;
            let mut buffer = [0u8; BUFFER_LENGTH];
            let offset: &mut usize = &mut 0;
            let v: u8 = if chain.is_main_net() { DASH_PUBKEY_ADDRESS } else { DASH_PUBKEY_ADDRESS_TEST };
            let h160 = hash160::Hash::from_slice(data)?;
            buffer.write(offset, v);
            buffer.write(offset, &h160);
            buffer.base_58_check()
        })
    }

    + (NSString *)addressWithPublicKeyData:(NSData *)data forChain:(DSChain *)chain {
        NSParameterAssert(data);
        NSParameterAssert(chain);

        NSMutableData *d = [NSMutableData secureDataWithCapacity:160 / 8 + 1];
        uint8_t version;
        UInt160 hash160 = data.hash160;

        if ([chain isMainnet]) {
            version = DASH_PUBKEY_ADDRESS;
        } else {
            version = DASH_PUBKEY_ADDRESS_TEST;
        }

        [d appendBytes:&version length:1];
        [d appendBytes:&hash160 length:sizeof(hash160)];
        return [NSString base58checkWithData:d];
    }
}*/
