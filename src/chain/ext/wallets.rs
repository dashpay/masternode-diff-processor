use std::time::SystemTime;
use bip0039::Language;
use crate::chain::{Chain, Wallet};
use crate::chain::ext::{Derivation, Settings};
use crate::chain::tx::ProviderRegistrationTransaction;
use crate::chain::wallet::seed::Seed;
use crate::crypto::{UInt160, UInt384};
use crate::storage::keychain::Keychain;
use crate::util::{Shared, TimeUtil};

pub trait Wallets {
    /// Merging Wallets
    fn wallet_having_identity_credit_funding_registration_hash(&self, credit_funding_registration_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_identity_credit_funding_topup_hash(&self, credit_funding_topup_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_identity_credit_funding_invitation_hash(&self, credit_funding_invitation_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_voting_authentication_hash(&self, voting_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_owner_authentication_hash(&self, owner_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_operator_authentication_key(&self, key: &UInt384) -> Option<(&Wallet, u32)>;
    fn wallet_containing_masternode_holding_address_for_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction) -> Option<(&Wallet, u32)>;

    // fn has_wallet_with_unique_id(&self, unique_id: &String) -> bool;
    // fn standard_wallet_with_seed_phrase<L: bip0039::Language>(&mut self, seed_phrase: &str, created_at: u64, store_seed_phrase: bool, is_transient: bool) -> Option<Wallet>;
    fn new_transient_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str) -> Option<Shared<Wallet>>;
    fn transient_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str, created_at: u64) -> Option<Shared<Wallet>>;
    fn standard_wallet_with_seed_phrase<L: bip0039::Language>(self, seed_phrase: &str, created_at: u64, is_transient: bool) -> Option<Shared<Wallet>>;
    fn transient_wallet_with_seed(self, seed: Seed) -> Shared<Wallet>;
    fn register_wallet(&self, wallet: Shared<Wallet>);
}

impl Wallets for Shared<Chain> {
    fn new_transient_wallet_with_seed_phrase<L: Language>(self, seed_phrase: &str) -> Option<Shared<Wallet>> {
        self.transient_wallet_with_seed_phrase::<L>(seed_phrase, SystemTime::seconds_since_1970())
    }

    fn transient_wallet_with_seed_phrase<L: Language>(self, seed_phrase: &str, created_at: u64) -> Option<Shared<Wallet>> {
        self.standard_wallet_with_seed_phrase::<L>(seed_phrase, created_at, true)
    }

    fn transient_wallet_with_seed(self, seed: Seed) -> Shared<Wallet> {
        self.with(|chain| {
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
                Keychain::save_seed_phrase(seed_phrase, created_at, seed.unique_id_as_str())
                    .ok()
                    .map(|()| {
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
            // chain.wallets.with(|wallets| {
                wallet.with(|w| {
                    println!("register_wallet.3: {:?}", w);
                    chain.wallets.push(w.clone());
                })
            // })
        });
    }

    fn wallet_having_identity_credit_funding_registration_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_identity_credit_funding_registration_hash(hash)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_having_identity_credit_funding_topup_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_identity_credit_funding_topup_hash(hash)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_having_identity_credit_funding_invitation_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_identity_credit_funding_invitation_hash(hash)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_having_provider_voting_authentication_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_provider_voting_authentication_hash(hash)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_having_provider_owner_authentication_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_provider_owning_authentication_hash(hash)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_having_provider_operator_authentication_key(&self, key: &UInt384) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         wallet.index_of_provider_operator_authentication_key(key)
        //             .map(|index| (wallet, index)))))
    }

    fn wallet_containing_masternode_holding_address_for_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction) -> Option<(&Wallet, u32)> {
        todo!()
        // self.with(|chain| chain.wallets.with(|wallets| wallets
        //     .iter()
        //     .find_map(move |wallet|
        //         transaction.outputs()
        //             .iter()
        //             .find_map(|output|
        //                 output.address.and_then(|a| wallet.index_of_holding_address(&a))
        //                     .map(|index| (wallet, index))))))
    }
}
