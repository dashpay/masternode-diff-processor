use hashes::hex::ToHex;
use secp256k1::Scalar;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, clone_into_array};
use crate::crypto::{ECPoint, UInt256, UInt512};
use crate::derivation::BIP32_HARD;
use crate::derivation::index_path::IIndexPath;

// multiplies secp256k1 generator by 256bit big endian int i and
// adds the result to ec-point self returns it on success
pub fn secp256k1_point_add(p: &ECPoint, i: &UInt256) -> ECPoint {
    // secp256k1::Signing + secp256k1::Verification
    let s = secp256k1::Secp256k1::new();
    let pub_key = secp256k1::PublicKey::from_slice(p.as_bytes()).unwrap();
    let tweak = Scalar::from_be_bytes(i.0).unwrap();
    let k = pub_key.add_exp_tweak(&s, &tweak).unwrap();
    ECPoint(k.serialize())
}

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
pub fn secp256k1_point_gen(i: &UInt256) -> ECPoint {
    let pub_key = secp256k1::PublicKey::from_slice(&i.0).unwrap();
    ECPoint(pub_key.serialize())
}
pub fn secp256k1_point_from_bytes(data: &[u8]) -> [u8; 33] {
    // let pub_key = secp256k1::PublicKey::from_slice(i).unwrap();
    let sec = secp256k1::SecretKey::from_slice(data).unwrap();
    let s = secp256k1::Secp256k1::new();
    let pub_key = secp256k1::PublicKey::from_secret_key(&s, &sec);
    pub_key.serialize()
}

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
pub fn secp256k1_mod_mul(a: &mut UInt256, b: &UInt256) -> secp256k1::SecretKey {
    let sec_key = secp256k1::SecretKey::from_slice(a.as_bytes()).unwrap();
    let tweak = Scalar::from_le_bytes(b.0).unwrap();
    sec_key.mul_tweak(&tweak).unwrap()
}

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
pub fn secp256k1_mod_add(a: &mut UInt256, b: &UInt256) -> secp256k1::SecretKey {
    // _ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    let sec_key = secp256k1::SecretKey::from_slice(a.as_bytes()).unwrap();
    let tweak = Scalar::from_le_bytes(b.0).unwrap();
    sec_key.add_tweak(&tweak).unwrap()
}

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

// Private parent key -> private child key
//
// CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
//       (Note: The 0x00 pads the private key to make it 33 bytes long.)
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key ki is parse256(IL) + kpar (mod n).
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i
//   (Note: this has probability lower than 1 in 2^127.)
//
pub trait ChildKeyDerivation {
    fn derive(&self, k: &mut UInt512, index: usize) where Self: IIndexPath;
}

// impl ChildKeyDerivation for IndexPath<u32> {
//     fn derive(&self, k: &mut UInt512, index: usize) where Self: IIndexPath {
//         let i = self.index_at_position(index);
//         let buf = &mut [0u8; 37];
//         if i & BIP32_HARD != 0 {
//             buf[1..33].clone_from_slice(&k.0[..32]);
//         } else {
//             buf[..33].clone_from_slice(&secp256k1_point_from_bytes(&k.0[..32]));
//         }
//         buf[33..37].clone_from_slice(i.to_be_bytes().as_slice());
//         ckd_priv(k, buf);
//     }
// }
//
// impl ChildKeyDerivation for IndexPath<UInt256> {
//     fn derive(&self, k: &mut UInt512, index: usize) where Self: IIndexPath {
//         let i = self.index_at_position(index);
//         let is_hardened = self.hardened_at_position(index);
//         let i_is_31_bits = i.is_31_bits();
//         let mut writer = Vec::<u8>::new();
//         if is_hardened {
//             0u8.enc(&mut writer);
//             writer.extend_from_slice(&k.0[..32]);
//         } else {
//             writer.extend_from_slice(&secp256k1_point_from_bytes(&k.0[..32]));
//         };
//         if i_is_31_bits {
//             let mut small_i = i.u32_le();
//             if is_hardened {
//                 small_i |= BIP32_HARD;
//             }
//             small_i.swap_bytes().enc(&mut writer);
//         } else {
//             i.enc(&mut writer);
//         };
//         ckd_priv(k, &writer)
//     }
// }

fn ckd_priv(k: &mut UInt512, key: &[u8]) {
    // I = HMAC-SHA512(c, k|P(k) || i)
    // k = IL + k (mod n)
    // c = IR
    // println!("ckd_priv.start: {} {}", k, key.to_hex());
    let i = UInt512::hmac(&k.0[32..], key);
    let mut sec_key = secp256k1::SecretKey::from_slice(&k.0[..32]).unwrap();
    let tweak = Scalar::from_be_bytes(clone_into_array(&i.0[..32])).unwrap();
    sec_key = sec_key.add_tweak(&tweak).unwrap();
    k.0[..32].clone_from_slice(&sec_key.secret_bytes());
    k.0[32..].clone_from_slice(&i.0[32..]);
    // println!("ckd_priv.end: {}", k);
}

pub fn derive_child_private_key(k: &mut UInt512, i: u32) {
    let buf = &mut [0u8; 37];
    if i & BIP32_HARD != 0 {
        buf[1..33].clone_from_slice(&k.0[..32]);
    } else {
        buf[..33].clone_from_slice(&secp256k1_point_from_bytes(&k.0[..32]));
    }
    buf[33..37].clone_from_slice(i.to_be_bytes().as_slice());
    ckd_priv(k, buf);
}

pub fn derive_child_private_key_256(k: &mut UInt512, i: &UInt256, hardened: bool) {
    let i_is_31_bits = i.is_31_bits();
    let mut writer = Vec::<u8>::new();
    if hardened {
        0u8.enc(&mut writer);
        writer.extend_from_slice(&k.0[..32]);
    } else {
        writer.extend_from_slice(&secp256k1_point_from_bytes(&k.0[..32]));
    };
    if i_is_31_bits {
        let mut small_i = i.u32_le();
        if hardened {
            small_i |= BIP32_HARD;
        }
        small_i.swap_bytes().enc(&mut writer);
    } else {
        i.enc(&mut writer);
    };
    ckd_priv(k, &writer)
}

// Public parent key -> public child key
//
// CKDpub((Kpar, cpar), i) -> (Ki, ci) computes a child extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): return failure
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key Ki is point(parse256(IL)) + Kpar.
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with
//   the next value for i.
//
fn ckd_pub(k: &mut ECPoint, c: &mut UInt256, key: &[u8]) {
    let key = UInt512::hmac(&c.0, key);
    c.0.copy_from_slice(&key.0[32..]);
    let s = secp256k1::Secp256k1::new();
    let mut pub_key = secp256k1::PublicKey::from_slice(&k.0).expect("invalid public key");
    let tweak = Scalar::from_be_bytes(clone_into_array(&key.0[..32])).expect("invalid tweak");
    pub_key = pub_key.add_exp_tweak(&s, &tweak).expect("failed to add tweak");
    k.0.copy_from_slice(pub_key.serialize().as_ref())
}

// I = HMAC-SHA512(c, P(K) || i)
// c = IR
// K = P(IL) + K
pub fn derive_child_public_key(k: &mut ECPoint, c: &mut UInt256, i: u32) {
    if i & BIP32_HARD != 0 {
        // can't derive private child key from public parent key
        return;
    }
    let writer = &mut [0u8; 37];
    writer[..33].clone_from_slice(&k.0);
    writer[33..].clone_from_slice(&i.to_be_bytes());
    ckd_pub(k, c, writer);
}

pub fn derive_child_public_key_256(k: &mut ECPoint, c: &mut UInt256, i: UInt256, hardened: bool) {
    if hardened {
        // can't derive private child key from public parent key
        return;
    }
    let mut writer = k.as_bytes().to_vec();
    if i.is_31_bits() {
        writer.extend_from_slice(&i.u32_le().to_be_bytes());
    } else {
        writer.extend_from_slice(i.as_bytes());
    };
    ckd_pub(k, c, &writer);
}
