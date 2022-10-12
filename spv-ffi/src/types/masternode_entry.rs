use crate::ffi::boxer::boxed;
use crate::types::masternode_entry_hash::MasternodeEntryHash;
use crate::types::operator_public_key::OperatorPublicKey;
use crate::types::validity::Validity;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dash_spv_primitives::crypto::byte_util::{UInt128, UInt160, UInt256, UInt384};
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MasternodeEntry {
    pub confirmed_hash: *mut [u8; 32],
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: *mut [u8; 32], // nullable
    pub is_valid: bool,
    pub key_id_voting: *mut [u8; 20],
    pub known_confirmed_at_height: u32, // nullable
    pub entry_hash: *mut [u8; 32],
    pub operator_public_key: *mut [u8; 48],
    pub previous_entry_hashes: *mut MasternodeEntryHash,
    pub previous_entry_hashes_count: usize,
    pub previous_operator_public_keys: *mut OperatorPublicKey,
    pub previous_operator_public_keys_count: usize,
    pub previous_validity: *mut Validity,
    pub previous_validity_count: usize,
    pub provider_registration_transaction_hash: *mut [u8; 32],
    pub ip_address: *mut [u8; 16],
    pub port: u16,
    pub update_height: u32,
}
impl<'a> TryRead<'a, Endian> for MasternodeEntry {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let provider_registration_transaction_hash =
            boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
        let confirmed_hash = boxed(bytes.read_with::<UInt256>(offset, LE)?.0);
        let ip_address = boxed(bytes.read_with::<UInt128>(offset, LE)?.0);
        let port = bytes.read_with::<u16>(offset, LE)?.swap_bytes();
        let operator_public_key = boxed(bytes.read_with::<UInt384>(offset, LE)?.0);
        let key_id_voting = boxed(bytes.read_with::<UInt160>(offset, LE)?.0);
        let is_valid = match bytes.read_with::<u8>(offset, LE) {
            Ok(data) => data,
            Err(_err) => 0,
        };
        Ok((
            Self {
                confirmed_hash,
                confirmed_hash_hashed_with_provider_registration_transaction_hash: null_mut(),
                is_valid: is_valid != 0,
                key_id_voting,
                known_confirmed_at_height: 0,
                entry_hash: null_mut(),
                operator_public_key,
                previous_entry_hashes: null_mut(),
                previous_entry_hashes_count: 0,
                previous_operator_public_keys: null_mut(),
                previous_operator_public_keys_count: 0,
                previous_validity: null_mut(),
                previous_validity_count: 0,
                provider_registration_transaction_hash,
                ip_address,
                port,
                update_height: 0,
            },
            *offset,
        ))
    }
}
