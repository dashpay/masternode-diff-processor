#[derive(Debug, Default, PartialEq)]
pub enum DerivationPathKind {
    #[default]
    Default,
    SimpleIndexed,
    AuthenticationKeys,
    Funds,
    IncomingFunds,
    CreditFunding,
    MasternodeHoldings,
}
