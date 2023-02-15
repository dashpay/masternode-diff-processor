use crate::chain::Chain;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::common::ChainType;
use crate::chain::wallet::seed::Seed;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::derivation::protocol::IDerivationPath;
use crate::util::Shared;

pub trait Derivation {
    fn register_derivation_paths_for_seed(&self, seed: &Seed, chain_type: ChainType);
    // fn identity_registration_funding_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> CreditFundingDerivationPath;
    // fn identity_topup_funding_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> CreditFundingDerivationPath;
    // fn identity_invitation_funding_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> CreditFundingDerivationPath;
    // fn identity_bls_keys_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> AuthenticationKeysDerivationPath;
    // fn identity_ecdsa_keys_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> AuthenticationKeysDerivationPath;

    // fn identity_funding_private_key_for_wallet(&self, wallet: &SharedWallet, coin_type: u32, is_for_invitation: bool, index: u32, seed: &Seed) -> Option<Key>;

    // fn identity_bls_keys_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key>;
    // fn identity_ecdsa_keys_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key>;
    // fn identity_registration_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key>;
    // fn identity_topup_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key>;
    // fn identity_invitation_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key>;

    // fn standard_derivation_paths_for_account_number(&self, account_number: u32) -> Vec<DerivationPathKind>;
    // fn register_specialized_derivation_paths_for_seed(&self, seed: &Seed);

    // fn provider_operator_keys_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> AuthenticationKeysDerivationPath;
    // fn provider_owner_keys_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> AuthenticationKeysDerivationPath;
    // fn provider_voting_keys_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> AuthenticationKeysDerivationPath;
    // fn provider_funds_derivation_path_for_wallet(&self, coin_type: u32, wallet: &SharedWallet) -> MasternodeHoldingsDerivationPath;
}

impl Derivation for Shared<Chain> {
    fn register_derivation_paths_for_seed(&self, seed: &Seed, chain_type: ChainType) {
        AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_chain(chain_type, self.borrow())
            .generate_extended_public_key_from_seed(seed);
        AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_chain(chain_type, self.borrow())
            .generate_extended_public_key_from_seed(seed);
        AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_chain(chain_type, self.borrow())
            .generate_extended_public_key_from_seed(seed);
        MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_chain(chain_type, self.borrow())
            .generate_extended_public_key_from_seed(seed);
        if chain_type.is_evolution_enabled() {
            AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_chain(chain_type, self.borrow())
                .generate_extended_public_key_from_seed(seed);
            AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_chain(chain_type, self.borrow())
                .generate_extended_public_key_from_seed(seed);
            CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_chain(chain_type, self.borrow())
                .generate_extended_public_key_from_seed(seed);
            CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_chain(chain_type, self.borrow())
                .generate_extended_public_key_from_seed(seed);
            CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_chain(chain_type, self.borrow())
                .generate_extended_public_key_from_seed(seed);
        }
    }

    // fn identity_funding_private_key_for_wallet(&self, wallet: &SharedWallet, coin_type: u32, is_for_invitation: bool, index: u32, seed: &Seed) -> Option<Key> {
    //     if is_for_invitation {
    //         self.identity_invitation_funding_derivation_path_for_wallet(coin_type, wallet)
    //     } else {
    //         self.identity_registration_funding_derivation_path_for_wallet(coin_type, wallet)
    //     }.private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
    // }

    // fn identity_bls_keys_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key> {
    //     self.identity_bls_keys_derivation_path_for_wallet(coin_type, wallet)
    //         .generate_extended_public_key_from_seed(seed)
    // }
    //
    // fn identity_ecdsa_keys_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key> {
    //     self.identity_ecdsa_keys_derivation_path_for_wallet(coin_type, wallet)
    //         .generate_extended_public_key_from_seed(seed)
    // }
    // fn identity_registration_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key> {
    //     self.identity_registration_funding_derivation_path_for_wallet(coin_type, wallet)
    //         .generate_extended_public_key_from_seed(seed)
    // }
    //
    // fn identity_topup_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key> {
    //     self.identity_topup_funding_derivation_path_for_wallet(coin_type, wallet)
    //         .generate_extended_public_key_from_seed(seed)
    // }
    //
    // fn identity_invitation_funding_extended_public_key_for_wallet_from_seed(&self, coin_type: u32, wallet: &SharedWallet, seed: &Seed) -> Option<Key> {
    //     self.identity_invitation_funding_derivation_path_for_wallet(coin_type, wallet)
    //         .generate_extended_public_key_from_seed(seed)
    // }

}

// pub struct DSChain {
//     pub wallets: Vec<DSWallet>,
// }
// pub struct DSWallet {
//     pub accounts: Vec<DSAccount>,
//     pub chain: DSChain,
// }
//
// pub struct DSAccount {
//     pub master_contacts_derivation_path: DSDerivationPath,
//     pub fund_derivation_paths: Vec<FundsDerivationPath>,
//     pub wallet: DSWallet,
// }
//
// impl Wallet {
//     pub fn standard_wallet_with_seed_phrase(phrase: &str, created_at: u64, chain: DSChain) -> Option<DSWallet> {
//         let account = DSAccount::account_with_number(0, chain.derivation_paths_for_account_number(0));
//         if let Some(unique_id) = Self::set_seed_phrase(phrase, created_at, chain) {
//             Self::registerDerivationPathsForSeedPhrase(phrase, unique_id, chain);
//             let wallet = DSWallet::initWithUniqueID(unique_id, vec![account], chain);
//             return Some(wallet);
//         }
//         None
//     }
// }
//
// impl DSAccount {
//     pub fn account_with_number(number: u32, derivation_paths: Vec<FundsDerivationPath>) -> DSAccount {
//         let account = Self {
//             master_contacts_derivation_path: (),
//             fund_derivation_paths: vec![],
//             wallet: DSWallet {}
//         }
//     }
// }

// + (instancetype)initWithAccountNumber:(uint32_t)accountNumber withDerivationPaths:(NSArray<DSFundsDerivationPath *> *)derivationPaths inContext:(NSManagedObjectContext *)context {
// if (!(self = [[super alloc] init])) return nil;
// _accountNumber = accountNumber;
// for (DSDerivationPath *derivationPath in derivationPaths) {
// [self.mFundDerivationPaths addObject:(DSFundsDerivationPath *)derivationPath];
// derivationPath.account = self;
// }
// return self;
// }
