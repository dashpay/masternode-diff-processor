use std::sync::{Arc, Mutex, Weak};
use crate::chain::Chain;
use crate::default_shared;
use crate::environment::{Environment, Language};
use crate::manager::authentication_manager::AuthenticationManager;
use crate::util::Shared;
use crate::util::shared::Shareable;

pub const DEVNET_CHAINS_KEY: &str = "DEVNET_CHAINS_KEY";

#[derive(Debug, Default)]
pub struct ChainsManager {
    pub mainnet: Shared<Chain>,
    pub testnet: Shared<Chain>,
    pub devnet_chains: Shared<Vec<Chain>>,
    pub environment: Environment,
    pub authentication_manager: AuthenticationManager,
}
default_shared!(Vec<Chain>);
impl Shareable for ChainsManager {}
impl ChainsManager {
    pub fn new() -> Self {
        ChainsManager {
            mainnet: Shared::Owned(Arc::new(Mutex::new(Chain::create_mainnet()))),
            testnet: Shared::Owned(Arc::new(Mutex::new(Chain::create_testnet()))),
            devnet_chains: Shared::Owned(Arc::new(Mutex::new(vec![]))),
            environment: Environment::new(Language::English),
            authentication_manager: AuthenticationManager::default()
        }
    }

}
