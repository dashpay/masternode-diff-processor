use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_ulong, c_void};
use std::ptr::null_mut;
use std::slice;
use byte::BytesExt;
use secp256k1::Scalar;
use crate::chain::bip::bip32;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::derivation::{BIP32_HARD, IndexPath};
use crate::chain::ScriptMap;
use crate::common::ChainType;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{clone_into_array, ConstDecodable};
use crate::crypto::{UInt256, UInt384, UInt512};
use crate::ffi::boxer::{boxed, boxed_vec};
use crate::ffi::{ByteArray, IndexPathData};
use crate::ffi::common::DerivationPathData;
use crate::ffi::unboxer::{unbox_any, unbox_opaque_key, unbox_opaque_keys, unbox_opaque_serialized_keys};
use crate::keys::{BLSKey, ECDSAKey, ED25519Key, IKey, KeyType};
use crate::keys::dip14::secp256k1_point_from_bytes;
use crate::processing::keys_cache::KeysCache;
use crate::types::opaque_key::{AsOpaque, KeyWithUniqueId, OpaqueKey, OpaqueKeys, OpaqueSerializedKeys};
use crate::util::address::address;
use crate::util::sec_vec::SecVec;

/// Destroys compact signature for ECDSAKey
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_compact_sig(ptr: *mut [u8; 65]) {
    unbox_any(ptr);
}
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_opaque_key(data: *mut OpaqueKey) {
    unbox_opaque_key(data);
}
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_opaque_keys(data: *mut OpaqueKeys) {
    unbox_opaque_keys(data);
}

#[no_mangle]
pub unsafe extern "C" fn processor_destroy_serialized_opaque_keys(data: *mut OpaqueSerializedKeys) {
    unbox_opaque_serialized_keys(data);
}

/// Initialize opaque cache to store keys information between FFI calls
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn keys_create_cache() -> *mut KeysCache {
    let cache = KeysCache::default();
    println!("keys_create_cache: {:?}", cache);
    boxed(cache)
}

/// Clear opaque key cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn keys_clear_cache(cache: *mut KeysCache) {
    println!("keys_clear_cache: {:p}", cache);
    (*cache).clear();
}

/// Destroy opaque key cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn keys_destroy_cache(cache: *mut KeysCache) {
    println!("keys_destroy_cache: {:?}", cache);
    let cache = unbox_any(cache);
}


/// Destroys anonymous internal holder for ECDSAKeyWithUniqueId
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_key_wrapper(key: *mut KeyWithUniqueId) {
    let k = unbox_any(key);
    unbox_any(k.ptr);
}

// /// Destroys anonymous internal holder for ECDSAKeyWithUniqueId
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn processor_destroy_ecdsa_key_wrapper(key: *mut ECDSAKeyWithUniqueId) {
//     unbox_any(key);
// }
//
// /// Destroys anonymous internal holder for BLSKeyWithUniqueId
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn processor_destroy_bls_key_wrapper(key: *mut BLSKeyWithUniqueId) {
//     unbox_any(key);
// }
//
// /// Destroys anonymous internal holder for ED25519KeyWithUniqueId
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn processor_destroy_ed25519_key_wrapper(key: *mut ED25519KeyWithUniqueId) {
//     unbox_any(key);
// }

/// Destroys anonymous internal holder for ECDSAKey
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_ecdsa_key(key: *mut ECDSAKey) {
    unbox_any(key);
}

/// Destroys anonymous internal holder for BLSKey
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_bls_key(key: *mut BLSKey) {
    unbox_any(key);
}

/// Destroys anonymous internal holder for ED25519Key
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_ed25519_key(key: *mut ED25519Key) {
    unbox_any(key);
}

/// Removes ECDSA key from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cache_remove_ecdsa_key(unique_id: u64, cache: *mut KeysCache) {
    let cache = &mut *cache;
    cache.ecdsa.remove(&unique_id);
}

/// Removes BLS key from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cache_key_remove_bls_key(unique_id: u64, cache: *mut KeysCache) {
    let cache = &mut *cache;
    cache.bls.remove(&unique_id);
}

/// Removes ED25519 key from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn cache_key_remove_ed25519_key(unique_id: u64, cache: *mut KeysCache) {
    let cache = &mut *cache;
    cache.ed25519.remove(&unique_id);
}

/// Replacement for [DSKey keyWithExtendedPublicKeyData]
/// Returns 'unique_id' (u64-equivalent for [DSDerivationPath createIdentifierForDerivationPath])
/// Then key can be removed by this 'unique_id'
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_ecdsa_from_extened_public_key_data(ptr: *const u8, len: usize, cache: *mut KeysCache) -> *mut KeyWithUniqueId {
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    ECDSAKey::key_with_extended_public_key_data(bytes)
        .map_or(null_mut(), |key| {
            let cache = &mut *cache;
            let unique_id = UInt256::sha256(bytes).u64_le();
            cache.ecdsa.insert(unique_id, key.clone());
            boxed(KeyWithUniqueId { key_type: KeyType::ECDSA, unique_id, ptr: boxed(key) as *mut c_void })
        })
}

/// Replacement for [DSKey keyWithExtendedPublicKeyData]
/// Returns 'unique_id' (u64-equivalent for [DSDerivationPath createIdentifierForDerivationPath])
/// Then key can be removed by this 'unique_id'
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_bls_from_extened_public_key_data(ptr: *const u8, len: usize, use_legacy: bool, cache: *mut KeysCache) -> *mut KeyWithUniqueId {
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    BLSKey::key_with_extended_public_key_data(bytes, use_legacy)
        .map_or(null_mut(), |key| {
            let bytes = unsafe { slice::from_raw_parts(ptr, len) };
            let cache = &mut *cache;
            let unique_id = UInt256::sha256(bytes).u64_le();
            cache.bls.insert(unique_id, key.clone());
            boxed(KeyWithUniqueId { key_type: if use_legacy { KeyType::BLS } else { KeyType::BLSBasic }, unique_id, ptr: boxed(key) as *mut c_void })
        })
}

/// Replacement for [DSKey keyWithExtendedPublicKeyData]
/// Returns 'unique_id' (u64-equivalent for [DSDerivationPath createIdentifierForDerivationPath])
/// Then key can be removed by this 'unique_id'
/// # Safety
#[no_mangle]
pub extern "C" fn key_create_ed25519_from_extened_public_key_data(ptr: *const u8, len: usize, cache: *mut KeysCache) -> *mut KeyWithUniqueId {
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    let cache = unsafe { &mut *cache };
    ED25519Key::key_with_extended_public_key_data(bytes)
        .map_or(null_mut(), |key| {
            let unique_id = UInt256::sha256(bytes).u64_le();
            cache.ed25519.insert(unique_id, key.clone());
            boxed(KeyWithUniqueId { key_type: KeyType::ED25519, unique_id, ptr: boxed(key) as *mut c_void })
        })
}

#[no_mangle]
pub extern "C" fn key_derive_key_from_extened_private_key_data_for_index_path(secret: *const u8, secret_len: usize, key_type: KeyType, indexes: *const c_ulong, length: usize) -> *mut OpaqueKey {
    let bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let path = IndexPath::from_ffi(indexes, length);
    match key_type {
        KeyType::ECDSA => ECDSAKey::key_with_extended_private_key_data(bytes)
            .and_then(|key| key.private_derive_to_path(&path))
            .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::BLS => BLSKey::key_with_extended_private_key_data(bytes, true)
            .and_then(|key| key.private_derive_to_path(&path))
            .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::BLSBasic => BLSKey::key_with_extended_private_key_data(bytes, false)
            .and_then(|key| key.private_derive_to_path(&path))
            .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::ED25519 => ED25519Key::key_with_extended_private_key_data(bytes)
            .and_then(|key| key.private_derive_to_path(&path))
            .map_or(null_mut(), |key| key.as_opaque()),
    }
}

#[no_mangle]
pub extern "C" fn key_derive_ecdsa_from_extened_private_key_data_for_index_path(secret: *const u8, secret_len: usize, indexes: *const c_ulong, length: usize) -> *mut ECDSAKey {
    let bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let path = IndexPath::from_ffi(indexes, length);
    ECDSAKey::key_with_extended_private_key_data(bytes)
        .and_then(|key| key.private_derive_to_path(&path))
        .map_or(null_mut(), boxed)
}

#[no_mangle]
pub extern "C" fn key_derive_bls_from_extened_private_key_data_for_index_path(secret: *const u8, secret_len: usize, indexes: *const c_ulong, length: usize, use_legacy: bool) -> *mut BLSKey {
    let bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let path = IndexPath::from_ffi(indexes, length);
    BLSKey::key_with_extended_private_key_data(bytes, use_legacy)
        .and_then(|key| key.private_derive_to_path(&path))
        .map_or(null_mut(), boxed)
}

#[no_mangle]
pub extern "C" fn key_derive_ed25519_from_extened_private_key_data_for_index_path(secret: *const u8, secret_len: usize, indexes: *const c_ulong, length: usize) -> *mut ED25519Key {
    let bytes = unsafe { slice::from_raw_parts(secret, secret_len) };
    let path = IndexPath::from_ffi(indexes, length);
    ED25519Key::key_with_extended_private_key_data(bytes)
        .and_then(|key| key.private_derive_to_path(&path))
        .map_or(null_mut(), boxed)
}


/// # Safety
/// digest is UInt256
#[no_mangle]
pub unsafe extern "C" fn key_sign_message_digest(key: *mut OpaqueKey, digest: *const u8) -> ByteArray {
    let key = unsafe { &mut *key };
    let message_digest = UInt256::from_const(digest).unwrap();
    match key.key_type {
        KeyType::ECDSA => ByteArray::from((&*(key.ptr as *mut ECDSAKey)).compact_sign(message_digest)),
        KeyType::BLS | KeyType::BLSBasic => ByteArray::from((&*(key.ptr as *mut BLSKey)).sign_digest(message_digest)),
        KeyType::ED25519 => ByteArray::from((&*(key.ptr as *mut ED25519Key)).sign(&message_digest.0))
    }
}

/// # Safety
/// digest is UInt256
#[no_mangle]
pub unsafe extern "C" fn key_verify_message_digest(key: *mut OpaqueKey, md: *const u8, sig: *const u8, sig_len: usize) -> bool {
    let key = unsafe { &mut *key };
    let digest = slice::from_raw_parts(md, 32);
    let signature = slice::from_raw_parts(sig, sig_len);
    match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).verify(digest, signature),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).verify(digest, signature),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).verify(digest, signature)
    }
}

/// # Safety
#[no_mangle]
pub extern "C" fn key_bls_sign_data(key: *mut BLSKey, ptr: *const u8, len: usize) -> ByteArray {
    let key = unsafe { &mut *key };
    let data = unsafe { slice::from_raw_parts(ptr, len) };
    ByteArray::from(key.sign_data(data))
    // boxed(key.sign_data(data).0)
}

/// # Safety
#[no_mangle]
pub extern "C" fn key_compact_sign_ecdsa(key: *mut ECDSAKey, digest: *const u8) -> *mut [u8; 65] {
    let key = unsafe { &mut *key };
    UInt256::from_const(digest)
        .map(|message_digest| key.compact_sign(message_digest))
        .map_or(null_mut(), boxed)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_ecdsa_with_seed_data(ptr: *const u8, len: usize) -> *mut ECDSAKey {
    let seed = slice::from_raw_parts(ptr, len);
    ECDSAKey::init_with_seed_data(seed)
        .map_or(null_mut(), boxed)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_ecdsa_with_private_key(secret: *const c_char, chain_id: i16) -> *mut ECDSAKey {
    let c_str = unsafe { CStr::from_ptr(secret) };
    let private_key_string = c_str.to_str().unwrap();
    let chain_type = ChainType::from(chain_id);
    ECDSAKey::key_with_private_key(private_key_string, chain_type)
        .map_or(null_mut(), |key| boxed(key))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_has_private_key(key: *mut OpaqueKey) -> bool {
    let key = &mut *key;
    match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).has_private_key(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).has_private_key(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).has_private_key(),
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_ecdsa_has_private_key(key: *mut ECDSAKey) -> bool {
    let key = &mut *key;
    key.has_private_key()
}

// serializedPrivateKeyForChain
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_ecdsa_serialized_private_key_for_chain(key: *mut ECDSAKey, chain_id: i16) -> *mut c_char {
    let key = &mut *key;
    let script = ScriptMap::from(chain_id);
    let serialized = key.serialized_private_key_for_script(&script);
    CString::new(serialized).unwrap().into_raw()
}

// + (NSString *)serializedAuthPrivateKeyFromSeed:(NSData *)seed forChain:(DSChain *)chain
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_ecdsa_serialized_auth_private_key_for_chain(seed: *const u8, seed_len: usize, chain_id: i16) -> *mut c_char {
    let seed = slice::from_raw_parts(seed, seed_len);
    let script_map = ScriptMap::from(chain_id);
    let serialized = ECDSAKey::serialized_auth_private_key_from_seed(seed, script_map);
    CString::new(serialized).unwrap().into_raw()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_ecdsa_from_secret(ptr: *const u8, len: usize, compressed: bool) -> *mut OpaqueKey {
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    ECDSAKey::key_with_secret_slice(bytes, compressed)
        .map_or(null_mut(), |key|
            boxed(OpaqueKey { key_type: KeyType::ECDSA, ptr: boxed(key) as *mut c_void }))
}


/// Deserializes extended private key from string and create opaque pointer to ECDSAKey
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_ecdsa_from_serialized_extended_private_key(key: *const c_char, chain_id: i16) -> *mut ECDSAKey {
    // NSData *extendedPrivateKey = [self deserializedExtendedPrivateKey:serializedExtendedPrivateKey onChain:chain];
    // [DSECDSAKey keyWithSecret:*(UInt256 *)extendedPrivateKey.bytes compressed:YES];
    (CStr::from_ptr(key).to_str().unwrap(), ChainType::from(chain_id))
        .try_into()
        .ok()
        .and_then(|key: bip32::Key| ECDSAKey::key_with_secret_data(&key.extended_key_data(), true))
        .map_or(null_mut(), boxed)
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_ecdsa_from_extended_public_key_data(ptr: *const u8, len: usize) -> *mut OpaqueKey {
    let bytes = slice::from_raw_parts(ptr, len);
    ECDSAKey::key_with_extended_public_key_data(bytes)
        .map_or(null_mut(), |key|
            boxed(OpaqueKey { key_type: KeyType::ECDSA, ptr: boxed(key) as *mut c_void }))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_with_public_key_data(ptr: *const u8, len: usize, key_type: KeyType) -> *mut OpaqueKey {
    let bytes = slice::from_raw_parts(ptr, len);
    match key_type {
        KeyType::ECDSA => ECDSAKey::key_with_public_key_data(bytes)
            .map(|key| key.as_opaque())
            .unwrap_or(null_mut()),
        KeyType::ED25519 => ED25519Key::key_with_public_key_data(bytes)
            .map(|key| key.as_opaque())
            .unwrap_or(null_mut()),
        KeyType::BLS => BLSKey::key_with_public_key(UInt384::from(bytes), true)
            .as_opaque(),
        KeyType::BLSBasic => BLSKey::key_with_public_key(UInt384::from(bytes), false)
            .as_opaque(),
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_from_extended_public_key_data(ptr: *const u8, len: usize, key_type: KeyType) -> *mut OpaqueKey {
    let bytes = slice::from_raw_parts(ptr, len);
    match key_type {
        KeyType::ECDSA => ECDSAKey::key_with_extended_public_key_data(bytes).map(|key| key.as_opaque()),
        KeyType::ED25519 => ED25519Key::key_with_extended_public_key_data(bytes).map(|key| key.as_opaque()),
        KeyType::BLS => BLSKey::key_with_extended_public_key_data(bytes, true).map(|key| key.as_opaque()),
        KeyType::BLSBasic => BLSKey::key_with_extended_public_key_data(bytes, false).map(|key| key.as_opaque()),
    }.unwrap_or(null_mut())
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_create_from_extended_private_key_data(ptr: *const u8, len: usize, key_type: KeyType) -> *mut OpaqueKey {
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    match key_type {
        KeyType::ECDSA => ECDSAKey::key_with_extended_private_key_data(bytes).map(|key| key.as_opaque()),
        KeyType::ED25519 => ED25519Key::key_with_extended_private_key_data(bytes).map(|key| key.as_opaque()),
        KeyType::BLS => BLSKey::key_with_extended_private_key_data(bytes, true).map(|key| key.as_opaque()),
        KeyType::BLSBasic => BLSKey::key_with_extended_private_key_data(bytes, false).map(|key| key.as_opaque()),
    }.unwrap_or(null_mut())
}

/// Deserializes extended private key from string and create opaque pointer to ECDSAKey
/// To pass NSIndexPath need to be serialized as byte array with u264 with path_length = bytes.length / 33
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_serialized_extended_private_key_from_seed(
    secret: *const u8,
    secret_len: usize,
    index_path: *const u8, // Vec<UInt256 + bool>
    path_length: usize,
    chain_id: i16) -> *mut c_char {
    let secret_slice = unsafe { slice::from_raw_parts(secret, secret_len) };
    let indexes_slice = unsafe { slice::from_raw_parts(index_path, 33 * path_length) };
    let chain_type = ChainType::from(chain_id);
    let index_path = indexes_slice.read_with::<IndexPath<UInt256>>(&mut 0, path_length).unwrap();
    ECDSAKey::serialized_extended_private_key_from_seed(secret_slice, index_path, chain_type)
        .map_or(null_mut(), |serialized| CString::new(serialized).unwrap().into_raw())
}

// #[no_mangle]
// pub extern "C" fn key_ecdsa_create_signature_for_tx_input_script(key: *mut ECDSAKey, ptr: *const u8, len: usize, chain_id: i16) -> *mut ffi::ByteArray {
//     let key = unsafe { &mut *key };
//     let in_script = unsafe { slice::from_raw_parts(ptr, len) };
//     let map = ChainType::from(chain_id).script_map();
//
//     // address::with_script_pub_key(&in_script.to_vec(), &map)
//     // key.address_with_public_key_data(&script_map)
// }



/// # Safety
#[no_mangle]
pub extern "C" fn ecdsa_public_key_hash_from_secret(secret: *const c_char, chain_id: i16) -> *mut [u8; 20] {
    let c_str = unsafe { CStr::from_ptr(secret) };
    let private_key_string = c_str.to_str().unwrap();
    let chain_type = ChainType::from(chain_id);
    ECDSAKey::key_with_private_key(private_key_string, chain_type)
        .map_or(null_mut(), |key| boxed(key.hash160().0))
}
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_address_for_key(key: *mut OpaqueKey, chain_id: i16) -> *mut c_char {
    let key = unsafe { &mut *key };
    let script_map = ScriptMap::from(chain_id);
    CString::new(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).address_with_public_key_data(&script_map),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).address_with_public_key_data(&script_map),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).address_with_public_key_data(&script_map)
    }).unwrap().into_raw()
}
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_address_with_public_key_data(data: *const u8, len: usize, chain_id: i16) -> *mut c_char {
    let map = ScriptMap::from(chain_id);
    let address = address::with_public_key_data(slice::from_raw_parts(data, len), &map);
    CString::new(address).unwrap().into_raw()
}
/// # Safety
#[no_mangle]
pub extern "C" fn address_for_ecdsa_key(key: *mut ECDSAKey, chain_id: i16) -> *mut c_char {
    let key = unsafe { &mut *key };
    let script_map = ScriptMap::from(chain_id);
    CString::new(key.address_with_public_key_data(&script_map))
        .unwrap()
        .into_raw()
}
/// # Safety
#[no_mangle]
pub extern "C" fn address_for_bls_key(key: *mut BLSKey, chain_id: i16) -> *mut c_char {
    let key = unsafe { &mut *key };
    let script_map = ScriptMap::from(chain_id);
    CString::new(key.address_with_public_key_data(&script_map))
        .unwrap()
        .into_raw()
}
/// # Safety
#[no_mangle]
pub extern "C" fn address_for_ed25519_key(key: *mut ED25519Key, chain_id: i16) -> *mut c_char {
    let key = unsafe { &mut *key };
    let script_map = ScriptMap::from(chain_id);
    CString::new(key.address_with_public_key_data(&script_map))
        .unwrap()
        .into_raw()
}

/// # Safety
#[no_mangle]
pub extern "C" fn address_for_ecdsa_key_recovered_from_compact_sig(data: *const u8, len: usize, digest: *const u8, chain_id: i16) -> *mut c_char {
    let compact_sig = unsafe { slice::from_raw_parts(data, len) };
    let script_map = ScriptMap::from(chain_id);
    UInt256::from_const(digest)
        .and_then(|message_digest| ECDSAKey::key_with_compact_sig(compact_sig, message_digest))
        .map_or(null_mut(), |key| CString::new(key.address_with_public_key_data(&script_map))
            .unwrap()
            .into_raw())
}
/// # Safety
#[no_mangle]
pub extern "C" fn ecdsa_public_key_unique_id_from_derived_key_data(data: *const u8, len: usize, chain_id: i16) -> u64 {
    let derived_key_data = unsafe { slice::from_raw_parts(data, len) };
    let seed_key = UInt512::bip32_seed_key(derived_key_data);
    let secret = UInt256::from(&seed_key.0[..32]);
    ECDSAKey::key_with_secret(&secret, true)
        .map_or(0, |public_key| {
            let data = public_key.public_key_data();
            let mut writer = SecVec::new();
            ChainType::from(chain_id).genesis_hash().enc(&mut writer);
            writer.extend(data);
            // one way injective function?
            UInt256::sha256(writer.as_slice()).u64_le()
        })
}

/// # Safety
#[no_mangle]
pub extern "C" fn ecdsa_address_from_public_key_data(data: *const u8, len: usize, chain_id: i16) -> *mut c_char {
    let public_key_data = unsafe { slice::from_raw_parts(data, len) };
    ECDSAKey::key_with_public_key_data(public_key_data)
        .map_or(null_mut(), |key|
            CString::new(key.address_with_public_key_data(&ScriptMap::from(chain_id)))
                .unwrap()
                .into_raw())
}


// - (DSKey *)generateExtendedPublicKeyFromSeed:(NSData *)seed storeUnderWalletUniqueId:(NSString *)walletUniqueId storePrivateKey:(BOOL)storePrivateKey;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn generate_extended_public_key_from_seed(seed: *const u8, seed_length: usize, key_type: KeyType, derivation_path: *const DerivationPathData) -> *mut OpaqueKey {
    let seed_bytes = slice::from_raw_parts(seed, seed_length);
    key_type.key_with_seed_data(seed_bytes)
        .and_then(|seed_key| seed_key.private_derive_to_256bit_derivation_path(&IndexPath::from(derivation_path)))
        .map_or(null_mut(), |extended_public_key| extended_public_key.as_opaque())
}
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn forget_private_key(key: *mut OpaqueKey) {
    let key = &mut *key;
    match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).forget_private_key(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).forget_private_key(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).forget_private_key()
    }
}


// _extendedPublicKey = [parentDerivationPath.extendedPublicKey publicDeriveTo256BitDerivationPath:self derivationPathOffset:parentDerivationPath.length];
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_public_derive_to_256bit(key: *mut OpaqueKey, derivation_path: *const DerivationPathData, offset: usize) -> *mut OpaqueKey {
    let key = &mut *key;
    let path = IndexPath::from(derivation_path);
    match key.key_type {
        KeyType::ECDSA =>
            (&mut *(key.ptr as *mut ECDSAKey))
                .public_derive_to_256bit_derivation_path_with_offset(&path, offset)
                .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::BLS | KeyType::BLSBasic =>
            (&mut *(key.ptr as *mut BLSKey))
                .public_derive_to_256bit_derivation_path_with_offset(&path, offset)
                .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::ED25519 =>
            (&mut *(key.ptr as *mut ED25519Key))
                .public_derive_to_256bit_derivation_path_with_offset(&path, offset)
                .map_or(null_mut(), |key| key.as_opaque())
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_private_key_data(key: *mut OpaqueKey) -> ByteArray {
    let key = &mut *key;
    ByteArray::from(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).private_key_data(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).private_key_data(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).private_key_data()
    })
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_public_key_data(key: *mut OpaqueKey) -> ByteArray {
    let key = &mut *key;
    ByteArray::from(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).public_key_data(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).public_key_data(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).public_key_data()
    })
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_extended_public_key_data(key: *mut OpaqueKey) -> ByteArray {
    let key = &mut *key;
    ByteArray::from(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).extended_public_key_data(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).extended_public_key_data(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).extended_public_key_data()
    })
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_extended_private_key_data(key: *mut OpaqueKey) -> ByteArray {
    let key = &mut *key;
    ByteArray::from(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).extended_private_key_data(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).extended_private_key_data(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).extended_private_key_data()
    })
}

// - (DSKey *)privateKeyAtIndexPath:(NSIndexPath *)indexPath fromSeed:(NSData *)seed;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_private_key_at_index_path(seed: *const u8, seed_length: usize, key_type: KeyType, index_path: *const IndexPathData, derivation_path: *const DerivationPathData) -> *mut OpaqueKey {
    let seed_bytes = slice::from_raw_parts(seed, seed_length);
    key_type.key_with_seed_data(seed_bytes)
        .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(&IndexPath::from(derivation_path)))
        .and_then(|path_extended_key| path_extended_key.private_derive_to_path(&IndexPath::from(index_path)))
        .map_or(null_mut(), |k| k.as_opaque())
}

// - (DSKey *)publicKeyAtIndexPath:(NSIndexPath *)indexPath;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_public_key_at_index_path(key: *mut OpaqueKey, index_path: *const IndexPathData) -> *mut OpaqueKey {
    let key = &mut *key;
    let index_path = IndexPath::from(index_path);
    match key.key_type {
        KeyType::ECDSA =>
            ECDSAKey::public_key_from_extended_public_key_data_at_index_path(&mut *(key.ptr as *mut ECDSAKey), &index_path)
                .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::BLS | KeyType::BLSBasic =>
            BLSKey::public_key_from_extended_public_key_data_at_index_path(&mut *(key.ptr as *mut BLSKey), &index_path)
                .map_or(null_mut(), |key| key.as_opaque()),
        KeyType::ED25519 =>
            ED25519Key::public_key_from_extended_public_key_data_at_index_path(&mut *(key.ptr as *mut ED25519Key), &index_path)
                .map_or(null_mut(), |key| key.as_opaque()),
    }
}

// - (NSData *)publicKeyDataAtIndexPath:(NSIndexPath *)indexPath;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_public_key_data_at_index_path(key: *mut OpaqueKey, index_path: *const IndexPathData) -> ByteArray {
    let key = &mut *key;
    let path = IndexPath::from(index_path);
    ByteArray::from(match key.key_type {
        KeyType::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(&(&mut *(key.ptr as *mut ECDSAKey)).extended_public_key_data().unwrap_or(vec![]), &path),
        KeyType::BLS => BLSKey::public_key_from_extended_public_key_data(&(&mut *(key.ptr as *mut BLSKey)).extended_public_key_data().unwrap_or(vec![]), &path, true),
        KeyType::BLSBasic => BLSKey::public_key_from_extended_public_key_data(&(&mut *(key.ptr as *mut BLSKey)).extended_public_key_data().unwrap_or(vec![]), &path, false),
        KeyType::ED25519 => ED25519Key::public_key_from_extended_public_key_data(&(&mut *(key.ptr as *mut ED25519Key)).extended_public_key_data().unwrap_or(vec![]), &path)
    })
}

//- (NSArray *)privateKeysAtIndexPaths:(NSArray *)indexPaths fromSeed:(NSData *)seed;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_private_keys_at_index_paths(
    seed: *const u8, seed_len: usize, key_type: KeyType,
    index_paths: *const IndexPathData,
    index_paths_len: usize,
    derivation_path: *const DerivationPathData) -> *mut OpaqueKeys {
    let seed_bytes = slice::from_raw_parts(seed, seed_len);
    let index_paths = slice::from_raw_parts(index_paths, index_paths_len);
    key_type.key_with_seed_data(seed_bytes)
        .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(&IndexPath::from(derivation_path)))
        .map_or(null_mut(), |derivation_path_extended_key| {
            let keys = index_paths.iter()
                .map(|p| derivation_path_extended_key.private_derive_to_path(&IndexPath::from(p as *const IndexPathData))
                    .map(|private_key| private_key.as_opaque()))
                .flatten()
                .collect::<Vec<_>>();
            let len = keys.len();
            boxed(OpaqueKeys { keys: boxed_vec(keys), len })
        })
}

//- (NSArray *)serializedPrivateKeysAtIndexPaths:(NSArray *)indexPaths fromSeed:(NSData *)seed
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn serialized_key_private_keys_at_index_paths(
    seed: *const u8, seed_len: usize, key_type: KeyType,
    index_paths: *const IndexPathData,
    index_paths_len: usize,
    derivation_path: *const DerivationPathData,
    chain_id: i16,
) -> *mut OpaqueSerializedKeys {
    let seed_bytes = slice::from_raw_parts(seed, seed_len);
    let index_paths = slice::from_raw_parts(index_paths, index_paths_len);
    key_type.key_with_seed_data(seed_bytes)
        .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(&IndexPath::from(derivation_path)))
        .map_or(null_mut(), |derivation_path_extended_key| {
            let script = ScriptMap::from(chain_id);
            let keys = index_paths.iter()
                .map(|p| derivation_path_extended_key.private_derive_to_path(&IndexPath::from(p as *const IndexPathData))
                    .map(|private_key| CString::new(private_key.serialized_private_key_for_script(&script))
                        .unwrap()
                        .into_raw()))
                .flatten()
                .collect::<Vec<_>>();
            let len = keys.len();
            boxed(OpaqueSerializedKeys { keys: boxed_vec(keys), len })
        })
}


// - (DSKey *)deprecatedIncorrectExtendedPublicKeyFromSeed:(NSData *)seed;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn deprecated_incorrect_extended_public_key_from_seed(seed: *const u8, seed_len: usize, derivation_path: *const DerivationPathData) -> *mut OpaqueKey {
    let i = UInt512::bip32_seed_key(slice::from_raw_parts(seed, seed_len));
    let secret = &i.0[..32];
    let mut writer = SecVec::new();
    let mut chaincode = UInt256::from(&i.0[32..]);
    ECDSAKey::key_with_secret_slice(secret, true)
        .and_then(|key| {
            key.hash160().u32_le().enc(&mut writer);
            let mut key = UInt256::from(secret);
            (0..(*derivation_path).len).into_iter().for_each(|position| {
                let index = (*derivation_path).indexes.offset(position as isize);
                let slice = slice::from_raw_parts(index as *const u8, 8);
                let soft_index = slice.read_with::<u64>(&mut 0, byte::BE).unwrap() as u32;
                let buf = &mut [0u8; 37];
                if soft_index & BIP32_HARD != 0 {
                    buf[1..33].copy_from_slice(&key.0);
                } else {
                    buf[..33].copy_from_slice(&secp256k1_point_from_bytes(&key.0));
                }
                buf[33..37].copy_from_slice(soft_index.to_be_bytes().as_slice());
                let i = UInt512::hmac(chaincode.as_ref(), buf);
                let mut sec_key = secp256k1::SecretKey::from_slice(&key.0).expect("invalid private key");
                let tweak = Scalar::from_be_bytes(clone_into_array(&i.0[..32])).expect("invalid tweak");
                sec_key = sec_key.add_tweak(&tweak).expect("failed to add tweak");
                key.0.copy_from_slice(&sec_key.secret_bytes());
                chaincode.0.copy_from_slice(&i.0[32..]);
            });
            if let Some(seckey) = ECDSAKey::key_with_secret(&key, true) {
                chaincode.enc(&mut writer);
                writer.extend(seckey.public_key_data());
                ECDSAKey::key_with_extended_public_key_data(&writer)
            } else {
                None
            }
        })
        .map_or(null_mut(), |key| key.as_opaque())
}

// + (NSData *)deserializedExtendedPrivateKey:(NSString *)extendedPrivateKeyString onChain:(DSChain *)chain;
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn deserialized_extended_private_key(ptr: *const c_char, chain_id: i16) -> ByteArray {
    ByteArray::from((CStr::from_ptr(ptr).to_str().unwrap(), ChainType::from(chain_id))
        .try_into()
        .ok()
        .map(|key: bip32::Key| key.extended_key_data()))
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn keys_public_key_data_is_equal(key1: *mut OpaqueKey, key2: *mut OpaqueKey) -> bool {
    let key1 = &mut *key1;
    let key2 = &mut *key2;
    match (key1.key_type, key2.key_type) {
        (KeyType::ECDSA, KeyType::ECDSA) =>
            (&mut *(key1.ptr as *mut ECDSAKey)).public_key_data() == (&mut *(key2.ptr as *mut ECDSAKey)).public_key_data(),
        (KeyType::BLS | KeyType::BLSBasic, KeyType::BLS | KeyType::BLSBasic) =>
            (&mut *(key1.ptr as *mut BLSKey)).public_key_data() == (&mut *(key2.ptr as *mut BLSKey)).public_key_data(),
        (KeyType::ED25519, KeyType::ED25519) =>
            (&mut *(key1.ptr as *mut ED25519Key)).public_key_data() == (&mut *(key2.ptr as *mut ED25519Key)).public_key_data(),
        _ => false
    }
}


// - (NSString *)serializedExtendedPublicKey;
// /// # Safety
// #[no_mangle]
// pub unsafe extern "C" fn serialized_extended_private_key(key: *mut OpaqueKey, depth: u8, chain_id: i16) -> *mut c_char {
//     // let key = &mut *key;
//     // let chain_type = ChainType::from(chain_id);
//     // match key.key_type {
//     //     KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).extended_public_key_data(),
//     //     KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).extended_public_key_data(),
//     //     KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).extended_public_key_data(),
//     // }.map(|ext_pub_key_data| {
//     //     let fingerprint = ext_pub_key_data.read_with::<u32>(&mut 0, byte::LE).unwrap();
//     //     let chain = ext_pub_key_data.read_with::<UInt256>(&mut 4, byte::LE).unwrap();
//     //     let pubkey = ext_pub_key_data.read_with::<ECPoint>(&mut 36, byte::LE).unwrap();
//     //
//     //     bip32::Key::new(depth, ext_pub_key_data.read)
//     // })
//     //
//     // NSData *extPubKeyData = self.extendedPublicKeyData;
//     // if (extPubKeyData.length < 36) return nil;
//     // uint32_t fingerprint = [extPubKeyData UInt32AtOffset:0];
//     // UInt256 chain = [extPubKeyData UInt256AtOffset:4];
//     // DSECPoint pubKey = [extPubKeyData ECPointAtOffset:36];
//     // UInt256 child = UINT256_ZERO;
//     // BOOL isHardened = NO;
//     // if (self.length) {
//     //     child = [self indexAtPosition:[self length] - 1];
//     //     isHardened = [self isHardenedAtPosition:[self length] - 1];
//     // }
//     //
//     // return serialize([self.depth unsignedCharValue], fingerprint, isHardened, child, chain, [NSData dataWithBytes:&pubKey length:sizeof(pubKey)], [self.chain isMainnet]);
//
// }

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn key_secret_key_string(key: *mut OpaqueKey) -> *mut c_char {
    let key = &mut *key;
    CString::new(match key.key_type {
        KeyType::ECDSA => (&mut *(key.ptr as *mut ECDSAKey)).secret_key_string(),
        KeyType::BLS | KeyType::BLSBasic => (&mut *(key.ptr as *mut BLSKey)).secret_key_string(),
        KeyType::ED25519 => (&mut *(key.ptr as *mut ED25519Key)).secret_key_string()
    }).unwrap().into_raw()

}

