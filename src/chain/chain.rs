use std::sync::{Arc, Mutex, Weak};
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::ext::Settings;
use crate::chain::params::{MAINNET_PARAMS, Params, TESTNET_PARAMS};
use crate::chain::Wallet;
use crate::common::Block;
use crate::default_shared;
use crate::derivation::factory::Factory;
use crate::manager::authentication_manager::AuthenticationManager;
use crate::storage::context::StoreContext;
use crate::util::shared::{Shareable, Shared};

#[derive(Clone, Debug, Default)]
pub struct Chain {
    pub params: Params,
    pub wallets: Shared<Vec<Wallet>>,
    pub store_context: StoreContext,
    pub derivation_factory: Arc<Factory>,

    pub last_sync_block: Option<Block>,
    pub authentication_manager: Shared<AuthenticationManager>,
}

impl Shareable for Chain {}

default_shared!(Chain);
default_shared!(Vec<Wallet>);

// impl PartialEq for Shared<Chain> {
//     fn eq(&self, other: &Self) -> bool {
//         self.with(|chain| chain).eq(&other.with(|chain| chain))
//     }
// }

// impl<'a> Default for &'a Chain<'a> {
//     fn default() -> &'a Chain<'a> {
//         static VALUE: Chain = Chain {
//             params: MAINNET_PARAMS,
//             wallets: vec![],
//             store_context: StoreContext::new_const_default(),
//             derivation_factory: Factory::new_const_default(),
//             // environment: Environment::new_const_default(),
//         };
//         &VALUE
//     }
// }

impl PartialEq<Self> for Chain {
    fn eq(&self, other: &Self) -> bool {
        self == other || other.r#type().genesis_hash().eq(&self.r#type().genesis_hash())
    }
}

impl Eq for Chain {}

impl Chain {
    pub fn create_mainnet() -> Self {
        Chain {
            params: MAINNET_PARAMS,
            wallets: Default::default(),
            store_context: Default::default(),
            derivation_factory: Arc::new(Default::default()),
            last_sync_block: None,
            authentication_manager: Default::default()
        }
    }

    pub fn create_testnet() -> Self {
        Chain {
            params: TESTNET_PARAMS,
            wallets: Default::default(),
            store_context: Default::default(),
            derivation_factory: Arc::new(Default::default()),
            last_sync_block: None,
            authentication_manager: Default::default()
        }
    }
}
