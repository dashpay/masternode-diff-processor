use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use crate::chain::wallet::Account;
use crate::chain::wallet::ext::constants::mnemonic_unique_id_for_unique_id;
use crate::chain::wallet::seed::Seed;
use crate::platform::identity::identity::Identity;
use crate::storage::keychain::Keychain;
use crate::{default_shared, UInt256, util};
use crate::chain::Chain;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::common::ChainType;
use crate::chain::ext::auth::Authentication;
use crate::chain::ext::wallets::Wallets;
use crate::derivation::derivation_path::DerivationPath;
use crate::derivation::funds_derivation_path::FundsDerivationPath;
use crate::util::shared::{Shareable, Shared};

pub type SeedCompletionBlock = fn(seed: Option<Vec<u8>>, cancelled: bool);

#[derive(Clone, Debug, Default)]
pub struct Wallet {
    pub chain: Shared<Chain>,

    pub accounts: HashMap<u32, Account>,
    pub identities: HashMap<UInt256, Identity>,

    is_transient: bool,
    unique_id_string: String,
}
impl Shareable for Wallet {}
default_shared!(Wallet);

impl PartialEq for Wallet {
    fn eq(&self, other: &Self) -> bool {
        /*self.chain == other.chain &&*/ self.unique_id_string.eq(other.unique_id_string())
        // self.chain.with(|chain| chain.eq(&other.chain.with(|other| other)) && self.unique_id_string.eq(other.unique_id_string()))
    }
}

//
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
    pub fn account_with_number(&self, account_number: u32) -> Option<&Account> {
        self.accounts.get(&account_number)
    }
    pub fn account_with_number_mut(&mut self, account_number: u32) -> Option<&mut Account> {
        self.accounts.get_mut(&account_number)
    }
}

impl Wallet {
    pub fn standard_wallet_with_seed(seed: Seed, account_number: u32, is_transient: bool, chain_type: ChainType, chain: Shared<Chain>) -> Shared<Wallet> {
        let mut account = Account::account_with_generated_extended_public_key_for_account_number(
            account_number,
            DerivationPath::master_identity_contacts_derivation_path_for_account_number(account_number, chain_type, chain.borrow()),
            if account_number == 0 { Some(FundsDerivationPath::bip32_derivation_path(account_number, chain_type, chain.borrow())) } else { None },
            FundsDerivationPath::bip44_derivation_path(account_number, chain_type, chain.borrow()),
            chain_type,
            &seed
        );
        account.generate_extended_public_keys_for_seed(&seed, chain_type.is_evolution_enabled());
        Self::init_with_unique_id_and_accounts(seed.unique_id.clone(), vec![account], is_transient, chain)
    }

    fn init_with_chain(chain: Shared<Chain>) -> Self {
        Self { chain, ..Default::default() }
    }

    fn init_with_chain_and_unique_id(unique_id: String, is_transient: bool, chain: Shared<Chain>) -> Self {
        let mut wallet = Self::init_with_chain(chain);
        wallet.unique_id_string = unique_id;
        wallet.is_transient = is_transient;
        wallet
    }

    fn init_with_unique_id_and_accounts(unique_id: String, accounts: Vec<Account>, is_transient: bool, chain: Shared<Chain>) -> Shared<Wallet> {
        let wallet = Self::init_with_chain_and_unique_id(unique_id.clone(), is_transient, chain.borrow());
        let mut shared_wallet = Shared::<Wallet>::Owned(Arc::new(Mutex::new(wallet)));
        // let shared_wallet = wallet.to_shared();
        // this must be last, as adding the account queries the wallet unique ID
        // wallet.add_accounts(accounts, shared_wallet.borrow());
        if !is_transient {
            chain.register_wallet(shared_wallet.borrow());
        }
        for mut account in accounts {
            account.bind_to_wallet_with_unique_id(unique_id.clone(), shared_wallet.borrow());
            // account.bind_to_wallet(shared_wallet.borrow());
            shared_wallet.borrow_mut().with(|w| {
                w.accounts.insert(account.account_number, account);
                let last_account_number = w.last_account_number();
                if last_account_number > w.accounts_known() {
                    Keychain::save_last_account_number(last_account_number, w.unique_id_as_str())
                        .expect("Can't save last_account_number in keychain");
                }
            });
        }
        // chain.loaded_specialized_derivation_paths_for_wallet(&wallet);
        // wallet.special_transactions_holder = SpecialTransactionWalletHolder::init_with_wallet(&wallet, chain.chain_context());
        //
        // wallet.identities.clear();
        // wallet.invitations.clear();
        // wallet.identities();
        // wallet.invitations();
        // blockchain users are loaded
        // add blockchain user derivation paths to account
        // shared_wallet.borrow()
        shared_wallet
    }

    fn add_account(&mut self, mut account: Account, shared: Shared<Wallet>) {
        account.bind_to_wallet_with_unique_id(self.unique_id_string.clone(), shared);
        // account.bind_to_wallet(shared);
        self.accounts.insert(account.account_number, account);
        let last_account_number = self.last_account_number();
        if last_account_number > self.accounts_known() {
            Keychain::save_last_account_number(last_account_number, self.unique_id_as_str())
                .expect("Can't save last_account_number in keychain");
        }
    }

    fn add_accounts(&mut self, accounts: Vec<Account>, shared: Shared<Wallet>) {
        accounts.into_iter().for_each(|account| self.add_account(account, shared.borrow()))
    }


    pub fn accounts_known_for_unique_id(unique_id: &str) -> u32 {
        Keychain::last_account_number(unique_id)
            .unwrap_or(0)
    }

    pub fn accounts_known(&self) -> u32 {
        Self::accounts_known_for_unique_id(self.unique_id_as_str())
    }

    pub fn load_identities(&self) {
        // TODO: impl storage
    }

    pub fn last_account_number(&self) -> u32 {
        assert!(!self.accounts.is_empty(), "There should always be at least one account");
        self.accounts.keys()
            .max()
            .unwrap_or(&u32::MAX)
            .clone()
    }

    /// Unique Identifiers

    pub fn mnemonic_unique_id(&self) -> String {
        mnemonic_unique_id_for_unique_id(self.unique_id_as_str())
    }
}

// async
impl Wallet {
    // authenticates user and returns seed
    pub fn seed_with_prompt(&self, authprompt: Option<String>, amount: u64) -> Result<(Option<Vec<u8>>, bool), util::Error> {
        self.chain.seed_with_prompt(authprompt, amount, self.unique_id_as_str())
    }
}


