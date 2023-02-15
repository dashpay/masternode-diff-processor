use std::collections::HashMap;
use crate::chain::{Chain, Wallet};
use crate::chain::common::ChainType;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::index_path::IIndexPath;
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::derivation::protocol::IDerivationPath;
use crate::util::Shared;

#[derive(Debug, Default)]
pub struct Factory {
    voting_keys_derivation_path_by_wallet: Option<HashMap<String, AuthenticationKeysDerivationPath>>,
    owner_keys_derivation_path_by_wallet: Option<HashMap<String, AuthenticationKeysDerivationPath>>,
    operator_keys_derivation_path_by_wallet: Option<HashMap<String, AuthenticationKeysDerivationPath>>,

    provider_funds_derivation_path_by_wallet: Option<HashMap<String, MasternodeHoldingsDerivationPath>>,

    identity_registration_funding_derivation_path_by_wallet: Option<HashMap<String, CreditFundingDerivationPath>>,
    identity_topup_funding_derivation_path_by_wallet: Option<HashMap<String, CreditFundingDerivationPath>>,
    identity_invitation_funding_derivation_path_by_wallet: Option<HashMap<String, CreditFundingDerivationPath>>,
    identity_bls_derivation_path_by_wallet: Option<HashMap<String, AuthenticationKeysDerivationPath>>,
    identity_ecdsa_derivation_path_by_wallet: Option<HashMap<String, AuthenticationKeysDerivationPath>>,
}

impl Factory {

    pub const fn new_const_default() -> Self {
        Self {
            voting_keys_derivation_path_by_wallet: None,
            owner_keys_derivation_path_by_wallet: None,
            operator_keys_derivation_path_by_wallet: None,
            provider_funds_derivation_path_by_wallet: None,
            identity_registration_funding_derivation_path_by_wallet: None,
            identity_topup_funding_derivation_path_by_wallet: None,
            identity_invitation_funding_derivation_path_by_wallet: None,
            identity_bls_derivation_path_by_wallet: None,
            identity_ecdsa_derivation_path_by_wallet: None
        }
    }

    pub fn new() -> Self {
        Self::new_const_default()
    }

    pub fn provider_operator_keys_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> AuthenticationKeysDerivationPath {
        let repo = self.operator_keys_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn provider_owner_keys_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> AuthenticationKeysDerivationPath {
        let repo = self.owner_keys_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn provider_voting_keys_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> AuthenticationKeysDerivationPath {
        let repo = self.voting_keys_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn provider_funds_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> MasternodeHoldingsDerivationPath {
        let repo = self.provider_funds_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn identity_registration_funding_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> CreditFundingDerivationPath {
        let repo = self.identity_registration_funding_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn identity_topup_funding_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> CreditFundingDerivationPath {
        let repo = self.identity_topup_funding_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn identity_invitation_funding_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> CreditFundingDerivationPath {
        let repo = self.identity_invitation_funding_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    /// Identity Authentication
    pub fn identity_bls_keys_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> AuthenticationKeysDerivationPath {
        let repo = self.identity_bls_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get(&unique_id).cloned().unwrap_or_else(|| {
            let path = AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn identity_ecdsa_keys_derivation_path_for_wallet(&mut self, chain_type: ChainType, unique_id: String, wallet: Shared<Wallet>, chain: Shared<Chain>) -> AuthenticationKeysDerivationPath {
        let repo = self.identity_ecdsa_derivation_path_by_wallet.get_or_insert(HashMap::new());
        repo.get_mut(&unique_id).cloned().unwrap_or_else(|| {
            let path = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(chain_type, wallet, chain, true);
            repo.insert(unique_id, path.clone());
            path
        })
    }

    pub fn loaded_specialized_derivation_paths_for_wallet(&mut self, chain_type: ChainType, wallet: Shared<Wallet>) -> Vec<DerivationPathKind> {
        todo!()
        // wallet.lock().ok()
        //     .and_then(|w| w.acquire_chain().map_or(vec![], |chain| ))
        // wallet.lock().ok()
        //     .and_then(|w| w.chain.upgrade())
        //     .map_or(
        //         vec![],
        //         |chain| {
        //             let mut arr: Vec<DerivationPathKind> = vec![
        //                 DerivationPathKind::from(self.provider_owner_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                 DerivationPathKind::from(self.provider_owner_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                 DerivationPathKind::from(self.provider_operator_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                 DerivationPathKind::from(self.provider_voting_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                 DerivationPathKind::from(self.provider_funds_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //             ];
        //             if chain.is_evolution_enabled() {
        //                 arr.extend([
        //                     DerivationPathKind::from(self.identity_ecdsa_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                     DerivationPathKind::from(self.identity_bls_keys_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                     DerivationPathKind::from(self.identity_registration_funding_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                     DerivationPathKind::from(self.identity_topup_funding_derivation_path_for_wallet(coin_type, wallet, &chain)),
        //                 ]);
        //             }
        //             arr
        //         })
    }

    pub fn fund_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: Shared<Wallet>) -> Vec<DerivationPathKind> {
        wallet.with(|w| {
            let mut arr = Vec::<DerivationPathKind>::new();
            w.accounts.values().for_each(|account| {
                account.outgoing_fund_derivation_paths()
                    .iter()
                    .filter(|path| !path.is_empty() && !path.has_extended_public_key())
                    // We should only add derivation paths that are local (ie where we can rederivate)
                    // The ones that come from the network should be refetched.
                    .for_each(|path| arr.push(DerivationPathKind::from(path.clone())));
                account.fund_derivation_paths().iter().for_each(|path| {
                    arr.push(path.clone());
                });
            });
            arr
        })
    }

    pub fn specialized_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: Shared<Wallet>) -> Vec<DerivationPathKind> {
        todo!()
        // let mut arr = Vec::<DerivationPathKind>::new();
        // match  { }
        // wallet.lock().ok().and_then(|w| w.chain.upgrade().and_then(|c| {
        //     self.unloaded_specialized_derivation_paths_for_wallet(wallet, &c).iter().for_each(|path| {
        //         if path.has_extended_public_key() {
        //             arr.push(path.clone());
        //         }
        //     });
        //     match c.lock() {
        //         Ok(chain) => {
        //             if chain.is_evolution_enabled() {
        //                 wallet.accounts.values().for_each(|account| {
        //                     let mut path = DerivationPath::master_blockchain_identity_contacts_derivation_path_for_account_number(account.account_number, chain.r#type().coin_type(), &c);
        //                     path.wallet = Weak::new();
        //                     if path.has_extended_public_key() {
        //                         arr.push(DerivationPathKind::from(path));
        //                     }
        //                 });
        //             }
        //         },
        //         _ => arr
        //     }
        // });
        // arr
    }

    pub fn unloaded_specialized_derivation_paths_for_wallet(&self, wallet: &Shared<Wallet>, chain: &Shared<Chain>) -> Vec<DerivationPathKind> {
        todo!()
        // let mut arr: Vec<DerivationPathKind> = vec![
        //     // Masternode
        //     DerivationPathKind::AuthenticationKeys(AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_wallet(wallet, chain)),
        //     DerivationPathKind::AuthenticationKeys(AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_wallet(wallet, chain)),
        //     DerivationPathKind::AuthenticationKeys(AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_wallet(wallet, chain)),
        //     DerivationPathKind::MasternodeHoldings(MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_wallet(wallet, chain)),
        // ];
        // if chain.is_evolution_enabled() {
        //     // Identities
        //     arr.extend([
        //         DerivationPathKind::AuthenticationKeys(AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(wallet, chain)),
        //         DerivationPathKind::AuthenticationKeys(AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_wallet(wallet, chain)),
        //         DerivationPathKind::CreditFunding(CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_wallet(wallet, chain)),
        //         DerivationPathKind::CreditFunding(CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_wallet(wallet, chain)),
        //         DerivationPathKind::CreditFunding(CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_wallet(wallet, chain)),
        //     ]);
        // }
        // arr
    }

    // pub fn register_specialized_derivation_paths_for_seed_phrase(&self, seed_phrase: &str, wallet_unique_id: &String, chain: &'a Chain) {
    //     if let Ok(seed_phrase) = bip39::Mnemonic::parse_normalized(seed_phrase) {
    //         let derived_key_data = seed_phrase.to_seed_normalized("").to_vec();
    //         let mut provider_owner_keys_path = AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_chain(chain);
    //         provider_owner_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //         let mut provider_operator_keys_path = AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_chain(chain);
    //         provider_operator_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //         let mut provider_voting_keys_path = AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_chain(chain);
    //         provider_voting_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //         let mut provider_funds_path = MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_chain(chain);
    //         provider_funds_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //         if chain.is_evolution_enabled() {
    //             let mut identity_bls_keys_path = AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_chain(chain);
    //             identity_bls_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //             let mut identity_ecdsa_keys_path = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_chain(chain);
    //             identity_ecdsa_keys_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //             let mut identity_registration_funding_path = CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_chain(chain);
    //             identity_registration_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //             let mut identity_topup_funding_path = CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_chain(chain);
    //             identity_topup_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //             let mut identity_invitation_funding_path = CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_chain(chain);
    //             identity_invitation_funding_path.generate_extended_public_key_from_seed(&derived_key_data, Some(wallet_unique_id));
    //         }
    //     }
    // }

}
