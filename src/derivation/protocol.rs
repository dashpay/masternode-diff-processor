use std::collections::HashSet;
use std::fmt::Debug;
use hashes::{Hash, sha256};
use crate::{derivation, util};
use crate::chain::{Chain, Wallet};
use crate::chain::ext::Settings;
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::index_path::{IIndexPath, IndexHardSoft, IndexPath};
use crate::derivation::uint256_index_path::UInt256IndexPath;
use crate::keys::{IKey, Key, KeyType};
use crate::storage::manager::managed_context::ManagedContext;
use crate::util::Address::with_public_key_data;
use crate::util::data_ops::short_hex_string_from;

pub trait IDerivationPath<IPATH: IIndexPath = UInt256IndexPath>: Send + Sync + Debug {
    fn chain(&self) -> &Chain;
    fn wallet(&self) -> Option<&Wallet>;
    fn context(&self) -> &ManagedContext;
    fn signing_algorithm(&self) -> KeyType;
    fn reference(&self) -> &DerivationPathReference;
    fn extended_public_key(&mut self) -> Option<Key>;
    fn extended_public_key_data(&mut self) -> Option<Vec<u8>> {
        self.extended_public_key().and_then(|mut key| key.extended_public_key_data())
    }
    fn has_extended_public_key(&self) -> bool;
    fn is_derivation_path_equal(&self, other: Self) -> bool where Self: Sized + PartialEq {
        *self == other
    }
    /// Purpose
    fn is_bip32_only(&self) -> bool where Self: IIndexPath {
        self.length() == 1
    }

    fn is_bip43_based(&self) -> bool where Self: IIndexPath {
        self.length() != 1
    }
    fn purpose(&self) -> u64 where Self: IIndexPath {
        if self.is_bip43_based() {
            self.index_at_position(0).softened()
        } else {
            0
        }
    }

    /// all previously generated addresses
    fn all_addresses(&self) -> HashSet<String>;
    /// all previously used addresses
    fn used_addresses(&self) -> HashSet<String>;
    /// true if the address is controlled by the wallet
    fn contains_address(&self, address: &String) -> bool {
        self.all_addresses().contains(address)
    }
    // gets an address at an index path
    fn address_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<String> {
        self.public_key_data_at_index_path(index_path)
            .map(|data| with_public_key_data(&data, &self.chain().script()))
    }
    // true if the address was previously used as an input or output in any wallet transaction
    fn address_is_used(&self, address: &String) -> bool {
        self.used_addresses().contains(address)
    }
    // true if the address at index path was previously used as an input or output in any wallet transaction
    fn address_is_used_at_index_path(&mut self, index_path: &IndexPath<u32>) -> bool {
        if let Some(address) = self.address_at_index_path(index_path) {
            self.address_is_used(&address)
        } else {
            false
        }
    }

    fn load_addresses(&mut self) {}
    fn reload_addresses(&mut self) {}
    // this returns the derivation path's visual representation (e.g. m/44'/5'/0')
    // fn string_representation(&mut self) -> &str;
    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String>;
    fn kind(&self) -> DerivationPathKind;
    fn balance(&self) -> u64;
    fn set_balance(&mut self, amount: u64);
    /// gets a private key at an index
    fn private_key_at_index(&self, index: u32, seed: &Vec<u8>) -> Option<Key> where Self: Sized + IIndexPath + IDerivationPath<IPATH> {
        self.private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
    }
    fn private_key_at_index_path_from_seed(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<Key> where Self: Sized + IIndexPath + IDerivationPath<IPATH> {
        self.signing_algorithm().key_with_seed_data(seed)
            .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                .and_then(|key| key.private_derive_to_path(index_path)))

    }

    fn private_keys_at_index_paths(&self, index_paths: Vec<IndexPath<u32>>, seed: &Vec<u8>) -> Vec<Key> where Self: Sized + IIndexPath + IDerivationPath<IPATH> {
        if index_paths.is_empty() {
            vec![]
        } else {
            self.signing_algorithm().key_with_seed_data(seed)
                .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                    .map(|key| index_paths.iter().filter_map(|index_path| key.private_derive_to_path(index_path)).collect::<Vec<_>>()))
                .unwrap_or(vec![])
        }
    }

    fn private_key_for_known_address(&self, address: &String, seed: &Vec<u8>) -> Option<Key> where Self: Sized + IIndexPath + IDerivationPath<IPATH> {
        self.index_path_for_known_address(address)
            .and_then(|index_path| self.private_key_at_index_path_from_seed(&index_path, seed))
    }

    fn public_key_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<Key> {
        self.public_key_data_at_index_path(index_path)
            .and_then(|data| self.signing_algorithm().key_with_public_key_data(&data))
    }

    fn public_key_data_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        self.extended_public_key_data()
            .and_then(|data| self.signing_algorithm().public_key_from_extended_public_key_data(&data, index_path))
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>>;
    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<Key>;

    fn register_transaction_address(&mut self, address: &String) -> bool;
    fn register_addresses_with_gap_limit(&mut self, gap_limit: u32) -> Result<Vec<String>, util::Error> {
        Err(util::Error::Default(format!("Should be overriden")))
    }

    fn register_addresses(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn create_identifier_for_derivation_path(&mut self) -> String {
        short_hex_string_from(&sha256::Hash::hash(&self.extended_public_key_data().unwrap_or(vec![])).into_inner())
    }

    fn standalone_extended_public_key_location_string(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id()
            .map(|unique_id| derivation::standalone_extended_public_key_location_string_for_unique_id(&unique_id))
    }

    fn standalone_info_dictionary_location_string(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id()
            .map(|unique_id| derivation::standalone_info_dictionary_location_string_for_unique_id(&unique_id))
    }

    fn wallet_based_extended_public_key_location_string_for_wallet_unique_id(&self, unique_id: &String) -> String where Self: IIndexPath {
        format!("{}{}{}",
                derivation::wallet_based_extended_public_key_location_string_for_unique_id(unique_id),
                self.signing_algorithm().derivation_string(),
                self.index_path_enumerated_string()
        )
    }

    /// Storage

    fn store_extended_public_key_under_wallet_unique_id(&mut self, wallet_unique_id: &String) -> bool where Self: IIndexPath {
        /*if let Some(mut key) = self.extended_public_key() {
            Keychain::set_data(self.wallet_based_extended_public_key_location_string_for_wallet_unique_id(wallet_unique_id), key.extended_public_key_data(), false)
                .expect("Can't store extended public key")
        } else {
            false
        }*/
        false
    }

    // fn load_identities(&self, address: &String) -> (Option<&Identity>, Option<&Identity>) {
    //     (None, None)
    // }
}

impl<IPATH: IIndexPath> PartialEq for dyn IDerivationPath<IPATH> {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}
