use std::collections::HashSet;
use crate::chain::{Chain, Wallet};
use crate::chain::wallet::Account;
use crate::UInt256;
use crate::chain::ext::Settings;
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::derivation::protocol::IDerivationPath;
use crate::derivation::uint256_index_path::UInt256IndexPath;
use crate::derivation::{standalone_extended_public_key_location_string_for_unique_id, wallet_based_extended_public_key_location_string_for_unique_id};
use crate::keys::IKey;
use crate::keys::key::{Key, KeyType};
use crate::storage::keychain::Keychain;
use crate::storage::manager::managed_context::ManagedContext;

#[derive(Debug, Default)]
pub struct DerivationPath {
    pub base: UInt256IndexPath,
    pub hardened_indexes: Vec<bool>,
    /// is this an open account
    pub r#type: DerivationPathType,
    pub signing_algorithm: KeyType,
    /// account for the derivation path
    pub chain: &'static Chain,
    /// account for the derivation path
    pub account: Option<&'static Account>,
    pub wallet: Option<&'static Wallet>,
    /// extended Public Key
    pub extended_public_key_data: Vec<u8>,
    /// extended Public Key Identifier, which is just the short hex string of the extended public key
    pub standalone_extended_public_key_unique_id: Option<String>,
    /// the wallet_based_extended_public_key_location_string is the key used to store the public key in the key chain
    pub wallet_based_extended_public_key_location_string: Option<String>,
    /// the wallet_based_extended_public_key_location_string is the key used to store the private key in the key chain,
    /// this is only available on authentication derivation paths
    pub wallet_based_extended_private_key_location_string: Option<String>,
    /// current derivation path balance excluding transactions known to be invalid
    pub balance: u64,
    /// purpose of the derivation path if BIP 43 based
    pub purpose: u64,
    /// currently the derivationPath is synced to this block height
    pub sync_block_height: u32,

    /// the reference of type of derivation path
    pub reference: DerivationPathReference,
    /// there might be times where the derivationPath is actually unknown, for example when importing from an extended public key
    pub derivation_path_is_known: bool,

    pub addresses_loaded: bool,

    pub all_addresses: Vec<String>,
    pub used_addresses: Vec<String>,

    pub standalone_extended_public_key_location_string: Option<String>,

    pub context: &'static ManagedContext,
    // @property (nonatomic, readonly) DSDerivationPathEntity *derivationPathEntity;

    /// private
    pub depth: u8,
    pub string_representation: Option<String>,

    // master public key used to generate wallet addresses
    extended_public_key: Option<Key>,
}

impl PartialEq for DerivationPath {
    fn eq(&self, other: &Self) -> bool {
        self.standalone_extended_public_key_unique_id.eq(&other.standalone_extended_public_key_unique_id)
    }
}

impl IIndexPath for DerivationPath {
    type Item = UInt256;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { base: UInt256IndexPath::new(indexes), ..Default::default() }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.base.indexes
    }

    fn hardened_indexes(&self) -> &Vec<bool> {
        &self.base.hardened_indexes
    }
}

impl IDerivationPath for DerivationPath {
    fn chain(&self) -> &Chain {
        self.chain
    }

    fn wallet(&self) -> Option<&Wallet> {
        self.wallet.or(self.account.and_then(|acc| acc.wallet))
    }

    fn context(&self) -> &ManagedContext {
        self.context
    }

    fn signing_algorithm(&self) -> KeyType {
        self.signing_algorithm
    }

    fn reference(&self) -> &DerivationPathReference {
        &self.reference
    }

    fn extended_public_key(&mut self) -> Option<Key> {
        self.extended_public_key.clone().or({
            let key_path = if self.wallet.is_some() && (!self.base.is_empty() || self.reference == DerivationPathReference::Root) {
                self.wallet_based_extended_public_key_location_string()
            } else {
                self.standalone_extended_public_key_location_string().unwrap()
            };
            Keychain::get_data(key_path).ok().and_then(|data| {
                self.extended_public_key = self.signing_algorithm.key_with_extended_public_key_data(&data);
                self.extended_public_key.clone()
            })
        })
    }

    fn has_extended_public_key(&self) -> bool {
        self.extended_public_key.is_some() || (self.wallet.is_some() && Keychain::has_data(if !self.base.is_empty() || self.reference == DerivationPathReference::Root {
            wallet_based_extended_public_key_location_string_for_unique_id(self.wallet.unwrap().unique_id_string())
        } else {
            standalone_extended_public_key_location_string_for_unique_id(self.wallet.unwrap().unique_id_string())
        }).unwrap_or(false))
    }

    fn all_addresses(&self) -> HashSet<String> {
        HashSet::from_iter(self.all_addresses.clone().into_iter())
    }

    fn used_addresses(&self) -> HashSet<String> {
        HashSet::from_iter(self.used_addresses.clone().into_iter())
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id.clone().or({
            if self.extended_public_key.is_none() && self.wallet.is_none() {
                assert!(false, "we really should have a wallet");
                None
            } else {
                let id = Some(self.create_identifier_for_derivation_path());
                self.standalone_extended_public_key_unique_id = id.clone();
                id
            }
        })
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::Default
    }

    fn balance(&self) -> u64 {
        self.balance
    }

    fn set_balance(&mut self, amount: u64) {
        self.balance = amount;
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>> {
        panic!("This must be implemented in subclasses")
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<Key> {
        self.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        let has_addr = self.contains_address(address);
        if has_addr && !self.used_addresses.contains(address) {
            self.used_addresses.push(address.clone());
        }
        has_addr
    }
}

impl DerivationPath {
    pub fn serialized_private_keys_at_index_paths(&self, index_paths: Vec<IndexPath<u32>>, seed: Option<Vec<u8>>) -> Option<Vec<String>> {
        if seed.is_none() {
            return None;
        }
        if index_paths.is_empty() {
            return Some(vec![]);
        }
        let top_key_opt = self.signing_algorithm().key_with_seed_data(&seed.unwrap());
        if top_key_opt.is_none() {
            return Some(vec![]);
        }
        let derivation_path_extended_key_opt = top_key_opt.unwrap().private_derive_to_256bit_derivation_path(self);
        if derivation_path_extended_key_opt.is_none() {
            return Some(vec![]);
        }
        let derivation_path_extended_key = derivation_path_extended_key_opt.unwrap();
        Some(index_paths.into_iter()
            .filter_map(|index_path| derivation_path_extended_key.private_derive_to_path(&index_path)
                .map(|key| key.serialized_private_key_for_chain(self.chain.script()))).collect())
    }

    pub fn wallet_based_extended_public_key_location_string(&mut self) -> String {
        self.wallet_based_extended_public_key_location_string.clone().unwrap_or({
            let str = wallet_based_extended_public_key_location_string_for_unique_id(self.wallet.unwrap().unique_id_string());
            self.wallet_based_extended_public_key_location_string = Some(str.clone());
            str
        })
    }

    /// Key Generation
    pub fn generate_extended_public_key_from_seed_and_store_private_key(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>, store_private_key: bool) -> Option<Key> {
        if seed.is_empty() || (self.base.is_empty() && !DerivationPathReference::Root.eq(self.reference())) {
            return None;
        }
        self.extended_public_key = self.signing_algorithm().private_derive_to_256bit_derivation_path_from_seed_and_store(seed, self, wallet_unique_id, store_private_key);
        self.extended_public_key.clone()
    }
}
