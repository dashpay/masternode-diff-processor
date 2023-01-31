use crate::chain::Wallet;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Account {
    pub wallet: Option<&'static Wallet>,
}
