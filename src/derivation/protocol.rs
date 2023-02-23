use std::collections::HashSet;
use std::fmt::Debug;
use byte::BytesExt;
use hashes::{Hash, sha256};
use hashes::hex::ToHex;
use crate::{derivation, UInt256, util};
use crate::chain::{Chain, Wallet};
use crate::chain::bip::bip32;
use crate::chain::bip::bip32::StringKey;
use crate::chain::common::ChainType;
use crate::chain::wallet::seed::Seed;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::index_path::{IIndexPath, IndexHardSoft, IndexPath};
use crate::derivation::uint256_index_path::UInt256IndexPath;
use crate::derivation::{standalone_extended_public_key_location_string_for_unique_id, wallet_based_extended_public_key_location_string_for_unique_id};
use crate::keys::{IKey, Key, KeyType};
use crate::util::Address::with_public_key_data;
use crate::util::data_ops::short_hex_string_from;
use crate::util::shared::Shared;

pub trait IDerivationPath<IPATH: IIndexPath = UInt256IndexPath>: Send + Sync + Debug {
    fn chain(&self) -> &Shared<Chain>;
    fn chain_type(&self) -> ChainType;
    fn wallet(&self) -> &Option<Shared<Wallet>>;
    fn set_wallet(&mut self, wallet: Shared<Wallet>);
    fn wallet_unique_id(&self) -> Option<String>;
    fn set_wallet_unique_id(&mut self, unique_id: String);
    fn set_wallet_with_unique_id(&mut self, wallet: Shared<Wallet>, unique_id: String) {
        self.set_wallet_unique_id(unique_id);
        self.set_wallet(wallet);
    }
    // https://github.com/rust-lang/rust/issues/94980
    // fn params(&self) -> &Params;
    // fn context(&self) -> Weak<ManagedContext>;
    fn signing_algorithm(&self) -> KeyType;
    fn reference(&self) -> DerivationPathReference;
    fn extended_public_key(&self) -> Option<Key>;
    fn extended_public_key_mut(&mut self) -> Option<Key>;
    fn extended_public_key_data(&self) -> Option<Vec<u8>> {
        self.extended_public_key().and_then(|key| key.extended_public_key_data())
    }
    fn extended_public_key_data_mut(&mut self) -> Option<Vec<u8>> {
        self.extended_public_key_mut().and_then(|key| key.extended_public_key_data())
    }
    fn private_key_from_seed(&self, seed: &Vec<u8>) -> Option<Key> where Self: IIndexPath<Item = UInt256> {
        self.signing_algorithm()
            .key_with_seed_data(seed)
            .and_then(|seed_key| seed_key.private_derive_to_256bit_derivation_path(self))
    }

    fn has_extended_public_key(&self) -> bool;
    fn serialized_extended_public_key(&self) -> Option<String> where Self: IIndexPath<Item = UInt256> {
        // todo make sure this works with BLS keys
        match self.extended_public_key_data() {
            Some(key_data) if key_data.len() >= 36 => {
                println!("serialized_extended_public_key.key_data: {}", key_data.to_hex());
                let fingerprint = key_data.read_with::<u32>(&mut 0, byte::LE).unwrap();
                let chain = key_data.read_with::<UInt256>(&mut 4, byte::LE).unwrap();
                // let pub_key = key_data.read_with::<ECPoint>(&mut 36, byte::LE).unwrap();
                let pubkey = key_data[36..].to_vec();
                let (child, is_hardened) = if self.is_empty() {
                    (UInt256::MIN, false)
                } else {
                    (self.last_index(), self.last_hardened())
                };
                Some(StringKey::serialize(self.depth(), fingerprint, is_hardened, child, chain, pubkey, self.chain_type()))
            },
            _ => None
        }
    }
    fn serialized_extended_public_key_mut(&mut self) -> Option<String> where Self: IIndexPath<Item = UInt256> {
        // todo make sure this works with BLS keys
        match self.extended_public_key_data() {
            Some(key_data) if key_data.len() >= 36 => {
                let fingerprint = key_data.read_with::<u32>(&mut 0, byte::LE).unwrap();
                let chain = key_data.read_with::<UInt256>(&mut 4, byte::LE).unwrap();
                // let pub_key = key_data.read_with::<ECPoint>(&mut 36, byte::LE).unwrap();
                let pubkey = key_data[36..].to_vec();
                let (child, is_hardened) = if self.is_empty() {
                    (UInt256::MIN, false)
                } else {
                    (self.last_index(), self.last_hardened())
                };
                Some(StringKey::serialize(self.depth(), fingerprint, is_hardened, child, chain, pubkey, self.chain_type()))
            },
            _ => None
        }
    }
    fn serialized_extended_private_key_from_seed(&self, seed: &Vec<u8>) -> Option<String> where Self: IIndexPath<Item = UInt256> {
        self.private_key_from_seed(seed)
            .map(|seed_key| bip32::Key::new(
                self.length() as u8,
                seed_key.fingerprint(),
                self.last_index(),
                seed_key.chaincode(),
                seed_key.secret_key().0.to_vec(),
                self.last_hardened())
                .serialize(self.chain_type()))
    }
    fn is_derivation_path_equal(&self, other: &Self) -> bool where Self: Sized + PartialEq {
        self == other
    }
    fn is_wallet_based(&self) -> bool where Self: IIndexPath {
        !self.is_empty() || self.reference() == DerivationPathReference::Root
    }
    fn public_key_location_string_for_wallet_unique_id(&self, unique_id: &str) -> String where Self: IIndexPath {
        if self.is_wallet_based() {
            wallet_based_extended_public_key_location_string_for_unique_id(unique_id)
        } else {
            standalone_extended_public_key_location_string_for_unique_id(unique_id)
        }
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
    fn depth(&self) -> u8;

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
            .map(|data| with_public_key_data(&data, &self.chain_type().script_map()))
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
    // fn kind(&self) -> DerivationPathKind;
    fn balance(&self) -> u64;
    fn set_balance(&mut self, amount: u64);
    /// gets a private key at an index
    fn private_key_at_index(&self, index: u32, seed: &Seed) -> Option<Key>
        where Self: Sized + IDerivationPath + IIndexPath<Item = UInt256> {
        // where Self: Sized + IDerivationPath + ChildKeyDerivation {
        <Self as IDerivationPath<IPATH>>::private_key_at_index_path_from_seed(self, &IndexPath::index_path_with_index(index), seed)
        // self.private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
    }
    fn private_key_at_index_path_from_seed(&self, index_path: &IndexPath<u32>, seed: &Seed) -> Option<Key>
        // where Self: Sized + IDerivationPath + ChildKeyDerivation {
        where Self: Sized + IDerivationPath + IIndexPath<Item = UInt256> {
        <Self as IDerivationPath<IPATH>>::signing_algorithm(self)
            .key_with_seed_data(&seed.data)
            .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                .and_then(|key| key.private_derive_to_path(index_path)))

    }

    fn private_keys_at_index_paths(&self, index_paths: Vec<IndexPath<u32>>, seed: &Seed) -> Vec<Key>
        where Self: Sized + IDerivationPath + IIndexPath<Item = UInt256> {
        // where Self: Sized + IDerivationPath + ChildKeyDerivation {
        if index_paths.is_empty() {
            vec![]
        } else {
            <Self as IDerivationPath<IPATH>>::signing_algorithm(self)
                .key_with_seed_data(&seed.data)
                .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                    .map(|key| index_paths.iter()
                        .filter_map(|index_path| key.private_derive_to_path(index_path))
                        .collect::<Vec<_>>()))
                .unwrap_or(vec![])
        }
    }

    fn private_key_for_known_address(&self, address: &String, seed: &Seed) -> Option<Key>
        where Self: Sized + IDerivationPath + IIndexPath<Item = UInt256> {
        // where Self: Sized + IDerivationPath + ChildKeyDerivation {
        <Self as IDerivationPath<IPATH>>::index_path_for_known_address(self, address)
            .and_then(|index_path| <Self as IDerivationPath<IPATH>>::private_key_at_index_path_from_seed(self, &index_path, seed))
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
    fn generate_extended_public_key_from_seed(&mut self, seed: &Seed) -> Option<Key>;

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

    fn wallet_based_extended_public_key_location_string_for_wallet_unique_id<'a>(&self, unique_id: &'a str) -> String where Self: IIndexPath {
        derivation::wallet_based_extended_public_key_location_string_for_unique_id_and_key_type(unique_id, self.signing_algorithm(), self.index_path_enumerated_string())
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
    //     (None, None)Ar
    // }
}

impl<IPATH: IIndexPath> PartialEq for dyn IDerivationPath<IPATH> {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}
