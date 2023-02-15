use std::collections::{BTreeSet, HashMap};
use security_framework::os::macos::keychain::SecKeychain;
use crate::chain::wallet::ext::constants::{accounts_known_key_for_wallet_unique_id, creation_time_unique_id_for_unique_id, did_verify_creation_time_unique_id_for_unique_id, mnemonic_unique_id_for_unique_id};
use crate::derivation::{wallet_based_extended_private_key_location_string_for_unique_id, wallet_based_extended_public_key_location_string_for_unique_id_and_key_type};
use crate::keys::KeyType;

pub const SEC_ATTR_SERVICE: &str = "org.dashfoundation.dash-spv";

#[derive(Debug, Default)]
pub struct Keychain {}

impl Keychain {

    #[cfg(not(test))]
    fn default_keychain() -> Result<SecKeychain, security_framework::base::Error> {
        SecKeychain::default()
    }
    // cargo test -- --test-threads=1 or
    #[cfg(test)]
    fn default_keychain() -> Result<SecKeychain, security_framework::base::Error> {
        println!("Accessing default keychain...");
        use security_framework::os::macos::keychain::{CreateOptions, KeychainSettings};
        use std::env;
        use std::path::Path;
        let keychain_path = Path::new(env::current_dir().unwrap().as_path()).join("dash-spv.keychain");
        match CreateOptions::new()
            .password("")
            .create(keychain_path.clone()) {
            Ok(mut keychain) => {
                let mut settings = KeychainSettings::new();
                settings.set_lock_interval(Some(u32::MAX-1));
                keychain.set_settings(&settings).unwrap();
                keychain.unlock(Some("")).expect("Can't unlock keychain");
                println!("Keychain created at {:?}", keychain_path);
                Ok(keychain)
            },
            Err(err) if err.code() == -25296 => {
                println!("Keychain exist at {:?}, so'll use it", keychain_path);
                match SecKeychain::open(keychain_path) {
                    Ok(mut keychain) => {
                        keychain.unlock(Some("")).expect("Can't unlock keychain");
                        Ok(keychain)
                    },
                    _ => panic!("Can't create or open keychain")
                }
            },
            Err(err) => {
                println!("Keychain error {:?}: {:?}", err.code(), err.message());
                Err(err)
            }
        }
    }

    pub fn set_data(key: String, data: Option<Vec<u8>>, authenticated: bool) -> Result<(), security_framework::base::Error> {
        let account = key.as_str();
        Self::default_keychain()
            .and_then(|keychain| {
                match (data, keychain.find_generic_password(SEC_ATTR_SERVICE, account)) {
                    (Some(data), Ok((_, mut item))) =>
                        item.set_password(data.as_slice()),
                    (Some(data), Err(err)) =>
                        keychain.add_generic_password(SEC_ATTR_SERVICE, account, data.as_slice()),
                    (None, Ok((_, item))) => {
                        item.delete();
                        Ok(())
                    },
                    (None, Err(err)) => {
                        println!("Keychain error {:?}: {:?}", err.code(), err.message());
                        Err(err)
                    }
                }
            })
    }

    pub fn has_data(key: String) -> Result<(), security_framework::base::Error> {
        let account = key.as_str();
        Self::default_keychain()
            .and_then(|keychain|
                match keychain.find_generic_password(SEC_ATTR_SERVICE, account) {
                    Ok((_, _)) => Ok(()),
                    Err(err) => Err(err)
                })
    }

    pub fn get_data(key: String) -> Result<Vec<u8>, security_framework::base::Error> {
        let account = key.as_str();
        Self::default_keychain()
            .and_then(|keychain|
                keychain.find_generic_password(SEC_ATTR_SERVICE, account)
                    .map(|(password, item)| password.to_vec()))
    }

    pub fn set_int(i: i64, key: String, authenticated: bool) -> Result<(), security_framework::base::Error> {
        Self::set_data(key, Some(i.to_le_bytes().to_vec()), authenticated)
    }

    pub fn get_int(key: String) -> Result<i64, security_framework::base::Error> {
        Self::get_data(key)
            .map(|data| data.try_into()
                .map(|bytes: [u8; 8]| i64::from_le_bytes(bytes)).unwrap_or(0))
    }

    pub fn set_string(s: String, key: String, authenticated: bool) -> Result<(), security_framework::base::Error> {
        Self::set_data(key, Some(s.as_bytes().to_vec()), authenticated)
    }

    pub fn get_string(key: String) -> Result<String, security_framework::base::Error> {
        Self::get_data(key).map(|data| String::from_utf8(data).unwrap_or("".to_string()))
    }

    pub fn set_dict<K, V>(dict: HashMap<K, V>, key: String, authenticated: bool) -> Result<(), security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_dict<K, V>(key: String) -> Result<HashMap<K, V>, security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_array<V>(arr: Vec<V>, key: String, authenticated: bool) -> Result<(), security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_array<V>(key: String, classes: Vec<String>) -> Result<Vec<V>, security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_ordered_set<V>(arr: BTreeSet<V>, key: String, authenticated: bool) -> Result<(), security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_ordered_set<V>(key: String, classes: Vec<String>) -> Result<BTreeSet<V>, security_framework::base::Error> {
        todo!("Implement bindings for keychain")
    }

    // pub fn set_object<T>(object: Box<dyn IKeychainObject<T>>, key: String, authenticated: bool) -> Result<bool, KeychainError> {
    //     todo!("Implement bindings for keychain")
    // }
    //
    // pub fn get_object<T>(key: String) -> Result<dyn IKeychainObject<T>, KeychainError> {
    //     todo!("Implement bindings for keychain")
    // }

    // pub fn set_json(dict: serde_json::Value, key: String, authenticated: bool) -> Result<bool, KeychainError> {
    //     todo!("Implement bindings for keychain")
    // }
    //
    // pub fn get_json(key: String) -> Result<serde_json::Value, KeychainError> {
    //     todo!("Implement bindings for keychain")
    // }

}

impl Keychain {
    pub fn save_seed_phrase(phrase: &str, created_at: u64, unique_id: &str) -> Result<(), security_framework::base::Error> {
        assert_ne!(created_at, 0, "error setting wallet");
        // in version 2.0.0 wallet creation times were migrated from reference date,
        // since this is now fixed just add this line so verification only happens once
        // Self::set_string(phrase.to_string(), mnemonic_unique_id_for_unique_id(unique_id), true)
        //     .and(Self::set_data(creation_time_unique_id_for_unique_id(unique_id), Some(created_at.to_le_bytes().to_vec()), false))
        //     .and(Self::set_int(1, did_verify_creation_time_unique_id_for_unique_id(unique_id), false))

        match Self::set_string(phrase.to_string(), mnemonic_unique_id_for_unique_id(unique_id), true) {
            Ok(()) => {
                match Self::set_data(creation_time_unique_id_for_unique_id(unique_id), Some(created_at.to_le_bytes().to_vec()), false) {
                    Ok(()) => {
                        match Self::set_int(1, did_verify_creation_time_unique_id_for_unique_id(unique_id), false) {
                            Ok(()) => Ok(()),
                            Err(err) => {
                                println!("Keychain error.3 {:?}: {:?}", err.code(), err.message());
                                Err(err)
                            }

                        }
                    },
                    Err(err) => {
                        println!("Keychain error.2 {:?}: {:?}", err.code(), err.message());
                        Err(err)
                    }
                }
            },
            Err(err) if err.code() == -25299 => match Self::set_data(creation_time_unique_id_for_unique_id(unique_id), Some(created_at.to_le_bytes().to_vec()), false) {
                Ok(()) => {
                    match Self::set_int(1, did_verify_creation_time_unique_id_for_unique_id(unique_id), false) {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            println!("Keychain error.23 {:?}: {:?}", err.code(), err.message());
                            Err(err)
                        }

                    }
                },
                Err(err) => {
                    println!("Keychain error.22 {:?}: {:?}", err.code(), err.message());
                    Err(err)
                }
            },
            Err(err) => {
                println!("Keychain error.1 {:?}: {:?}", err.code(), err.message());
                Err(err)
            }
        }

    }

    pub fn mnemonic(wallet_unique_id: &str) -> Result<String, security_framework::base::Error> {
        Self::get_string(mnemonic_unique_id_for_unique_id(wallet_unique_id))
    }

    pub fn save_last_account_number(number: u32, wallet_unique_id: &str) -> Result<(), security_framework::base::Error> {
        Self::set_int(number as i64, accounts_known_key_for_wallet_unique_id(wallet_unique_id), false)
    }

    pub fn last_account_number(wallet_unique_id: &str) -> Result<u32, security_framework::base::Error> {
        Self::get_int(accounts_known_key_for_wallet_unique_id(wallet_unique_id))
            .map(|i| i as u32)
    }

    pub fn save_extended_public_key(wallet_unique_id: &str, r#type: KeyType, index_path: String, data: Option<Vec<u8>>) -> Result<(), security_framework::base::Error> {
        Self::set_data(
            wallet_based_extended_public_key_location_string_for_unique_id_and_key_type(
                wallet_unique_id,
                r#type,
                index_path), data, false)
    }

    pub fn save_extended_private_key(wallet_unique_id: &str, data: Option<Vec<u8>>) -> Result<(), security_framework::base::Error> {
        Self::set_data(wallet_based_extended_private_key_location_string_for_unique_id(wallet_unique_id), data, true)
    }
}
