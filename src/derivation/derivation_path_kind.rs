use std::collections::HashSet;
use crate::chain::{Chain, Wallet};
use crate::chain::common::ChainType;
use crate::chain::wallet::seed::Seed;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path::DerivationPath;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::funds_derivation_path::FundsDerivationPath;
use crate::derivation::incoming_funds_derivation_path::IncomingFundsDerivationPath;
use crate::derivation::index_path::IndexPath;
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::derivation::protocol::IDerivationPath;
use crate::derivation::simple_indexed_derivation_path::SimpleIndexedDerivationPath;
use crate::keys::{Key, KeyType};
use crate::util::Shared;

#[derive(Clone, Debug, PartialEq)]
pub enum DerivationPathKind {
    Default(DerivationPath),
    SimpleIndexed(SimpleIndexedDerivationPath),
    AuthenticationKeys(AuthenticationKeysDerivationPath),
    Funds(FundsDerivationPath),
    IncomingFunds(IncomingFundsDerivationPath),
    CreditFunding(CreditFundingDerivationPath),
    MasternodeHoldings(MasternodeHoldingsDerivationPath),
}

impl From<DerivationPath> for DerivationPathKind {
    fn from(value: DerivationPath) -> Self {
        DerivationPathKind::Default(value)
    }
}
impl From<SimpleIndexedDerivationPath> for DerivationPathKind {
    fn from(value: SimpleIndexedDerivationPath) -> Self {
        DerivationPathKind::SimpleIndexed(value)
    }
}
impl From<AuthenticationKeysDerivationPath> for DerivationPathKind {
    fn from(value: AuthenticationKeysDerivationPath) -> Self {
        DerivationPathKind::AuthenticationKeys(value)
    }
}
impl From<FundsDerivationPath> for DerivationPathKind {
    fn from(value: FundsDerivationPath) -> Self {
        DerivationPathKind::Funds(value)
    }
}
impl From<IncomingFundsDerivationPath> for DerivationPathKind {
    fn from(value: IncomingFundsDerivationPath) -> Self {
        DerivationPathKind::IncomingFunds(value)
    }
}
impl From<CreditFundingDerivationPath> for DerivationPathKind {
    fn from(value: CreditFundingDerivationPath) -> Self {
        DerivationPathKind::CreditFunding(value)
    }
}
impl From<MasternodeHoldingsDerivationPath> for DerivationPathKind {
    fn from(value: MasternodeHoldingsDerivationPath) -> Self {
        DerivationPathKind::MasternodeHoldings(value)
    }
}

impl DerivationPathKind {
    pub fn path_mut(&mut self) -> &mut dyn IDerivationPath {
        match self {
            DerivationPathKind::Default(path) => path,
            DerivationPathKind::SimpleIndexed(path) => path,
            DerivationPathKind::AuthenticationKeys(path) => path,
            DerivationPathKind::Funds(path) => path,
            DerivationPathKind::IncomingFunds(path) => path,
            DerivationPathKind::CreditFunding(path) => path,
            DerivationPathKind::MasternodeHoldings(path) => path
        }
    }
    pub fn path(&self) -> &dyn IDerivationPath {
        match self {
            DerivationPathKind::Default(path) => path,
            DerivationPathKind::SimpleIndexed(path) => path,
            DerivationPathKind::AuthenticationKeys(path) => path,
            DerivationPathKind::Funds(path) => path,
            DerivationPathKind::IncomingFunds(path) => path,
            DerivationPathKind::CreditFunding(path) => path,
            DerivationPathKind::MasternodeHoldings(path) => path
        }
    }
}

impl IDerivationPath for DerivationPathKind {
    fn chain(&self) -> &Shared<Chain> {
        self.path().chain()
    }

    fn chain_type(&self) -> ChainType {
        self.path().chain_type()
    }

    fn wallet(&self) -> &Option<Shared<Wallet>> {
        self.path().wallet()
    }

    fn set_wallet(&mut self, wallet: Shared<Wallet>) {
        self.path_mut().set_wallet(wallet);
    }

    fn wallet_unique_id(&self) -> Option<String> {
        self.path().wallet_unique_id()
    }

    fn set_wallet_unique_id(&mut self, unique_id: String) {
        self.path_mut().set_wallet_unique_id(unique_id);
    }
    // fn params(&self) -> &Params {
    //     self.path().params()
    // }
    //
    // fn wallet(&self) -> Weak<Wallet> {
    //     self.path().wallet()
    // }
    //
    // fn context(&self) -> Weak<ManagedContext> {
    //     self.path().context()
    // }

    fn signing_algorithm(&self) -> KeyType {
        self.path().signing_algorithm()
    }

    fn reference(&self) -> DerivationPathReference {
        self.path().reference()
    }

    fn extended_public_key(&self) -> Option<Key> {
        self.path().extended_public_key()
    }

    fn extended_public_key_mut(&mut self) -> Option<Key> {
        self.path_mut().extended_public_key_mut()
    }

    fn has_extended_public_key(&self) -> bool {
        self.path().has_extended_public_key()
    }

    fn depth(&self) -> u8 {
        self.path().depth()
    }

    fn all_addresses(&self) -> HashSet<String> {
        self.path().all_addresses()
    }

    fn used_addresses(&self) -> HashSet<String> {
        self.path().used_addresses()
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.path_mut().standalone_extended_public_key_unique_id()
    }

    fn balance(&self) -> u64 {
        self.path().balance()
    }

    fn set_balance(&mut self, amount: u64) {
        self.path_mut().set_balance(amount);
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>> {
        self.path().index_path_for_known_address(address)
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Seed) -> Option<Key> {
        self.path_mut().generate_extended_public_key_from_seed(seed)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        self.path_mut().register_transaction_address(address)
    }
}
