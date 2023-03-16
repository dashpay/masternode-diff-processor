use crate::crypto::ECPoint;
use crate::UInt256;

pub trait DIP14<T> {
    fn derive_child_private_key     (k: &mut T,         c: &mut UInt256, i: u32);
    fn derive_child_private_key_256 (k: &mut T,         c: &mut UInt256, i: UInt256, hardened: bool);

    fn derive_child_public_key      (k: &mut ECPoint,   c: &mut UInt256, i: u32);
    fn derive_child_public_key_256  (k: &mut ECPoint,   c: &mut UInt256, i: UInt256, hardened: bool);
}

// pub fn derive_child_private_key(k: &mut UInt512, i: u32);
// pub fn derive_child_private_key_256(k: &mut UInt512, i: &UInt256, hardened: bool);
// pub fn derive_child_public_key(k: &mut ECPoint, c: &mut UInt256, i: u32);
// pub fn derive_child_public_key_256(k: &mut ECPoint, c: &mut UInt256, i: UInt256, hardened: bool);

// pub fn derive_child_private_key_ed25519(signing_key: &mut ed25519_dalek::SigningKey, chaincode: &mut UInt256, i: u32) {
// pub fn derive_child_private_key_256_ed25519(signing_key: &mut ed25519_dalek::SigningKey, chaincode: &mut UInt256, i: &UInt256, hardened: bool) {
// pub fn derive_child_public_key_ed25519(k: &mut ECPoint, c: &mut UInt256, i: u32) {
// pub fn derive_child_public_key_256_ed25519(k: &mut ECPoint, c: &mut UInt256, i: UInt256, hardened: bool) {
