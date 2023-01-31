use std::collections::{BTreeSet, HashMap};

#[derive(Debug)]
pub enum KeychainError {
    OsStatusError(i32, String),
    SerializationError(i32, String)
}

#[derive(Debug, Default)]
pub struct Keychain {

}

impl Keychain {
    pub fn set_data(key: String, data: Option<Vec<u8>>, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn has_data(key: String) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_data(key: String) -> Result<Vec<u8>, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_int(i: i64, key: String, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_int(key: String) -> Result<i64, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_string(s: String, key: String, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_string(key: String) -> Result<String, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_dict<K, V>(dict: HashMap<K, V>, key: String, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_dict<K, V>(key: String) -> Result<HashMap<K, V>, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_array<V>(arr: Vec<V>, key: String, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_array<V>(key: String, classes: Vec<String>) -> Result<Vec<V>, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn set_ordered_set<V>(arr: BTreeSet<V>, key: String, authenticated: bool) -> Result<bool, KeychainError> {
        todo!("Implement bindings for keychain")
    }

    pub fn get_ordered_set<V>(key: String, classes: Vec<String>) -> Result<BTreeSet<V>, KeychainError> {
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
