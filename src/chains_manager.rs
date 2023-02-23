use std::sync::{Arc, Mutex};
use crate::chain::Chain;
use crate::chain::common::ChainType;
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
            mainnet: Chain::create_mainnet(),
            testnet: Chain::create_testnet(),
            devnet_chains: Shared::Owned(Arc::new(Mutex::new(vec![]))),
            environment: Environment::new(Language::English),
            authentication_manager: AuthenticationManager::default()
        }
    }
    pub fn new_shared() -> Shared<Self> {
        Self::new().to_shared()
    }
}

impl ChainsManager {
    pub fn start_with_seed_phrase<L: bip0039::Language>(&self, seed_phrase: &str, chain_type: ChainType) {
        match chain_type {
            ChainType::MainNet => self.mainnet.start_with_seed_phrase::<L>(seed_phrase),
            ChainType::TestNet => self.testnet.start_with_seed_phrase::<L>(seed_phrase),
            ChainType::DevNet(_) => panic!("devnets aren't supported yet")
        }
    }
}
