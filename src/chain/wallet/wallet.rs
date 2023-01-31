use std::collections::HashMap;
use crate::chain::Chain;
use crate::chain::wallet::Account;
use crate::platform::identity::identity::Identity;
use crate::UInt256;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Wallet {
    pub chain: &'static Chain,
    pub accounts: HashMap<u32, Account>,
    pub identities: HashMap<UInt256, &'static Identity>,

    is_transient: bool,
    unique_id_string: String,
}

impl Wallet {
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }
    pub fn unique_id_string(&self) -> &String {
        &self.unique_id_string
    }
    pub fn unique_id_as_str(&self) -> &str {
        self.unique_id_string.as_str()
    }
}
