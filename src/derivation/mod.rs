pub mod derivation_path;
pub mod derivation_path_feature_purpose;
pub mod derivation_path_kind;
pub mod derivation_path_reference;
pub mod derivation_path_type;
pub mod funds_derivation_path;
pub mod incoming_funds_derivation_path;
pub mod index_path;
pub mod protocol;
pub mod sequence_gap_limit;
pub mod uint256_index_path;

use crate::chain::bip::bip32;
use crate::chain::params::Params;
use crate::storage::manager::managed_context::ManagedContext;
use crate::UInt256;

pub const BIP32_HARD: u32 = 0x80000000;
pub const BIP32_HARD_LE: u32 = 0x00000080;

pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION: &str = "DP_EPK_WBL";
pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION: &str = "DP_EPK_SBL";
pub const DERIVATION_PATH_EXTENDED_SECRET_KEY_WALLET_BASED_LOCATION: &str = "DP_ESK_WBL";
pub const DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION: &str = "DP_SIDL";
pub const DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX: &str = "DP_SI_T_INDEX";
pub const DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED: &str = "DP_SI_T_HARDENED";
pub const DERIVATION_PATH_STANDALONE_INFO_DEPTH: &str = "DP_SI_DEPTH";

pub fn string_representation_of_derivation_path_index(index: &UInt256, hardened: bool, context: Option<&ManagedContext>) -> String {
    let hardened_str = if hardened { "'" } else { "" };
    if index.is_31_bits() {
        format!("/{}{}", index.u64_le(), hardened_str)
    } /*else if let Some(context) = context {
        let mut s = String::new();
        context.perform_block_and_wait(|context| {
            s = match UserEntity::get_user_and_its_identity_username(index, context) {
                Ok((user_entity, identity_username_entity)) => format!("/{}{}", identity_username_entity.string_value, hardened_str),
                Err(err) => format!("/0x{}{}", index, hardened_str)
            }
        });
        s
    } */else {
        format!("/0x{}{}", index, hardened_str)
    }
}

fn standalone_extended_public_key_location_string_for_unique_id(unique_id: &String) -> String {
    format!("{}_{}", DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION, unique_id)
}

fn standalone_info_dictionary_location_string_for_unique_id(unique_id: &String) -> String {
    format!("{}_{}", DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION, unique_id)
}

fn wallet_based_extended_public_key_location_string_for_unique_id(unique_id: &String) -> String {
    format!("{}_{}", DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION, unique_id)
}

pub fn wallet_based_extended_private_key_location_string_for_unique_id(unique_id: &String) -> String {
    format!("{}_{}", DERIVATION_PATH_EXTENDED_SECRET_KEY_WALLET_BASED_LOCATION, unique_id)
}


fn deserialized_extended_public_key_for_chain(extended_public_key_string: &String, params: &Params) -> Result<bip32::Key, bip32::Error> {
    bip32::from(extended_public_key_string, params)
}
