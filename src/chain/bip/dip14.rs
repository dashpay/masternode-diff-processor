use secp256k1::Scalar;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, clone_into_array};
use crate::crypto::{ECPoint, UInt256, UInt512};
use crate::derivation::BIP32_HARD;

// multiplies secp256k1 generator by 256bit big endian int i and
// adds the result to ec-point self returns it on success
pub fn secp256k1_point_add(p: &ECPoint, i: &UInt256) -> ECPoint {
    // SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    let s = secp256k1::Secp256k1::new();
    let pub_key = secp256k1::PublicKey::from_slice(p.as_bytes()).unwrap();
    let tweak = Scalar::from_le_bytes(i.0).unwrap();
    let k = pub_key.add_exp_tweak(&s, &tweak).unwrap();
    ECPoint(k.serialize())
}

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
pub fn secp256k1_point_gen(i: &UInt256) -> ECPoint {
    let pub_key = secp256k1::PublicKey::from_slice(i.as_bytes()).unwrap();
    ECPoint(pub_key.serialize())
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
fn _ckd_priv(k: &mut UInt256, mut c: UInt256, key: &[u8]) {
    // I = HMAC-SHA512(c, k|P(k) || i)
    // k = IL + k (mod n)
    // c = IR
    let i = UInt512::hmac(key, &c.0);
    c = UInt256(clone_into_array(&i.0[..32]));
    secp256k1_mod_add(k, &c);
}


pub fn ckd_priv(mut k: UInt256, c: UInt256, i: u32) {
    let buf = &mut [0u8; 65];
    if i & BIP32_HARD != 0 {
        buf[1..33].clone_from_slice(k.as_bytes());
    } else {
        buf[..33].clone_from_slice(secp256k1_point_gen(&k).as_bytes());
    }
    buf[33..37].clone_from_slice(i.to_le_bytes().as_slice());
    _ckd_priv(&mut k, c, buf);
}

pub fn ckd_priv_256(mut k: UInt256, c: UInt256, i: &UInt256, hardened: bool) {
    let i_is_31_bits = i.is_31_bits();
    let mut writer = Vec::<u8>::new();
    if hardened {
        0u8.enc(&mut writer);
        k.enc(&mut writer);
    } else {
        secp256k1_point_gen(&k).enc(&mut writer);
    };
    if i_is_31_bits {
        i.u32_le().swap_bytes().enc(&mut writer);
    } else {
        i.enc(&mut writer);
    };
    _ckd_priv(&mut k, c, writer.as_slice());
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
fn _ckd_pub(k: ECPoint, mut c: UInt256, key: &[u8]) -> ECPoint {
    // I = HMAC-SHA512(c, P(K) || i)
    let i = UInt512::hmac(key, &c.0);
    // c = IR
    c = UInt256(clone_into_array(&i.0[..32]));
    // K = P(IL) + K
    secp256k1_point_add(&k, &c)
}

pub fn ckd_pub(k: ECPoint, c: UInt256, i: u32) -> ECPoint {
    if i & BIP32_HARD != 0 {
        // can't derive private child key from public parent key
        return k;
    }
    _ckd_pub(k, c, &i.swap_bytes().to_le_bytes())
}

pub fn ckd_pub_256(k: ECPoint, c: UInt256, i: UInt256, hardened: bool) -> ECPoint {
    if hardened {
        // can't derive private child key from public parent key
        return k;
    }
    let i_is_31_bits = i.is_31_bits();
    if i_is_31_bits {
        _ckd_pub(k, c, &i.u32_le().swap_bytes().to_le_bytes())
    } else {
        _ckd_pub(k, c, i.as_bytes())
    }
    // let buf = if i_is_31_bits {
    //
    // } else {
    //     i.0
    // };
    // let buf = if i_is_31_bits {
    //     &i.u32_le().swap_bytes().to_le_bytes()
    // } else {
    //     i.as_bytes()
    // };
    // _ckd_pub(k, c, buf)
}
