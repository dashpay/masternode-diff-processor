use std::time::SystemTime;
use bip0039::Language;
use crate::chain::{Chain, Wallet};
use crate::chain::ext::{Derivation, Settings};
use crate::chain::wallet::seed::Seed;
use crate::storage::keychain::Keychain;
use crate::util::{Shared, TimeUtil};

pub trait Wallets {
    /// Merging Wallets
    // fn wallet_having_identity_credit_funding_registration_hash(&self, credit_funding_registration_hash: &UInt160) -> Option<(&Wallet, u32)>;
    // fn wallet_having_identity_credit_funding_topup_hash(&self, credit_funding_topup_hash: &UInt160) -> Option<(&Wallet, u32)>;
    // fn wallet_having_identity_credit_funding_invitation_hash(&self, credit_funding_invitation_hash: &UInt160) -> Option<(&Wallet, u32)>;
    // fn wallet_having_provider_voting_authentication_hash(&self, voting_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    // fn wallet_having_provider_owner_authentication_hash(&self, owner_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    // fn wallet_having_provider_operator_authentication_key(&self, key: &UInt384) -> Option<(&Wallet, u32)>;
    // fn wallet_containing_masternode_holding_address_for_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction) -> Option<(&Wallet, u32)>;

    // fn has_wallet_with_unique_id(&self, unique_id: &String) -> bool;
    // fn standard_wallet_with_seed_phrase<L: bip0039::Language>(&mut self, seed_phrase: &str, created_at: u64, store_seed_phrase: bool, is_transient: bool) -> Option<Wallet>;
    fn new_transient_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str) -> Option<Shared<Wallet>>;
    fn transient_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str, created_at: u64) -> Option<Shared<Wallet>>;
    fn standard_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str, created_at: u64, is_transient: bool) -> Option<Shared<Wallet>>;
    fn transient_wallet_with_seed<L: Language>(self, seed: Seed) -> Shared<Wallet>;
    fn register_wallet(&self, wallet: Shared<Wallet>);
}

impl Wallets for Shared<Chain> {
    fn new_transient_wallet_with_seed_phrase<L: Language>(self, seed_phrase: &str) -> Option<Shared<Wallet>> {
        self.transient_wallet_with_seed_phrase::<L>(seed_phrase, SystemTime::seconds_since_1970())
    }

    fn transient_wallet_with_seed_phrase<L: Language>(self, seed_phrase: &str, created_at: u64) -> Option<Shared<Wallet>> {
        self.standard_wallet_with_seed_phrase::<L>(seed_phrase, created_at, true)
    }

    fn transient_wallet_with_seed<L: Language>(self, seed: Seed) -> Shared<Wallet> {
        self.with(|chain| {
            println!("transient_wallet_with_seed_data: {:?}", seed);
            self.register_derivation_paths_for_seed(&seed, chain.r#type());
            Wallet::standard_wallet_with_seed(
                seed,
                0,
                true,
                chain.r#type(),
                self.borrow())
        })
    }

    fn standard_wallet_with_seed_phrase<L: Language>(self, seed_phrase: &str, created_at: u64, is_transient: bool) -> Option<Shared<Wallet>> {
        self.with(|chain| Seed::from_phrase::<L>(seed_phrase, chain.genesis())
            .and_then(|seed| {
                println!("standard_wallet_with_seed_phrase: {:?}", seed);
                Keychain::save_seed_phrase(seed_phrase, created_at, seed.unique_id_as_str())
                    .ok()
                    .map(|()| {
                        println!("standard_wallet: seed saved");
                        self.register_derivation_paths_for_seed(&seed, chain.r#type());
                        Wallet::standard_wallet_with_seed(
                            seed,
                            0,
                            is_transient,
                            chain.r#type(),
                            self.borrow())
                    })
            }))
    }

    // registering wallet in chain allows to adjust bloom filter to
    // receiving wallet-related info like transactions etc
    fn register_wallet(&self, wallet: Shared<Wallet>) {
        println!("register_wallet.1: {:?}", wallet);
        self.with(|chain| {
            println!("register_wallet.2: {:?}", chain);
            chain.wallets.with(|wallets| {
                wallet.with(|w| {
                    println!("register_wallet.3: {:?}", w);
                    wallets.push(w.clone());
                })
            })
        });
    }
}

// impl Wallets for Chain {
//     fn standard_wallet_with_seed_phrase<L: bip0039::Language>(&mut self, seed_phrase: &str, created_at: u64, is_transient: bool) -> Option<Wallet> {
//         Seed::from_phrase::<L>(seed_phrase, self.r#type().genesis_hash())
//             .and_then(|seed| Keychain::save_seed_phrase(seed_phrase, created_at, seed.unique_id_as_str())
//                 .ok()
//                 .map(|()| {
//                     self.register_specialized_derivation_paths_for_seed(&seed);
//                     let account_number = 0;
//                     let derivation_paths = self.standard_derivation_paths_for_account_number(account_number);
//                     let context = self.chain_context();
//                     let mut wallet = Wallet::init_with_chain_and_unique_id(chain, seed.unique_id.clone());
//                     wallet.is_transient = is_transient;
//                     if !is_transient {
//                         chain.register_wallet(wallet)
//                     }
//                     // let account = Account::account_with_generated_extended_public_key_for_account_number(&wallet, account_number, &seed, derivation_paths, context);
//                     wallet
//                     // &wallet
//                 }))
//     }
// }


// impl Wallets for Arc<Chain> {
    // fn has_wallet_with_unique_id(&self, unique_id: &String) -> bool {
    //     self.wallets.iter().find(|w| unique_id.eq(w.unique_id_string())).is_some()
    // }


    // fn standard_wallet_with_seed_phrase<L: bip0039::Language>(&'a mut self, seed_phrase: &str, created_at: u64, store_seed_phrase: bool, is_transient: bool) -> Option<Wallet<'a>> {
    //     bip0039::Mnemonic::<L>::from_phrase(seed_phrase)
    //         .map(|mnemonic| mnemonic.to_seed(""))
    //         .ok()
    //         .and_then(|seed| {
    //             let unique_id = Wallet::unique_id_for_seed::<L>(seed, self.r#type().genesis_hash());
    //             match Keychain::save_seed_phrase(seed_phrase, created_at, unique_id.as_str()) {
    //                 Ok(()) => {
    //                     self.register_specialized_derivation_paths_for_seed_and_unique_id(&seed.to_vec(), &unique_id);
    //                     let account_number = 0;
    //                     let derivation_paths = self.standard_derivation_paths_for_account_number(account_number);
    //                     let context = self.chain_context();
    //                     let mut wallet = Wallet::init_with_chain_and_unique_id(self, unique_id);
    //                     if store_seed_phrase {
    //                         self.register_wallet(&wallet);
    //                     }
    //                     let account = Account::account_with_generated_extended_public_key_for_account_number(&wallet, account_number, unique_id.clone(), seed, derivation_paths, context);
    //                     Some(wallet)
    //
    //                 },
    //                 Err(err) => None
    //             }
    //         })
    // }
// }
