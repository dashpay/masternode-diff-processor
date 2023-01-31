use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::ext::Settings;
use crate::chain::params::{MAINNET_PARAMS, Params};
use crate::chain::Wallet;

#[derive(Debug, Default)]
pub struct Chain {
    pub params: Params,
    pub wallets: Vec<&'static Wallet>,
}

impl<'a> Default for &'a Chain {
    fn default() -> &'a Chain {
        static VALUE: Chain = Chain {
            params: MAINNET_PARAMS,
            wallets: vec![]
        };
        &VALUE
    }
}

impl PartialEq<Self> for Chain {
    fn eq(&self, other: &Self) -> bool {
        self == other || other.r#type().genesis_hash().eq(&self.r#type().genesis_hash())
    }
}

impl Eq for Chain {}
