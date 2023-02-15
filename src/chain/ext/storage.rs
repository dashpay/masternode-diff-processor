use crate::chain::Chain;
use crate::storage::context_type::ContextType;
use crate::storage::manager::managed_context::ManagedContext;

pub trait Storage {
    fn chain_context(&self) -> &ManagedContext;
    fn masternodes_context(&self) -> &ManagedContext;
    fn peer_context(&self) -> &ManagedContext;
    fn platform_context(&self) -> &ManagedContext;
    fn view_context(&self) -> &ManagedContext;
}

impl Storage for Chain {
    fn chain_context(&self) -> &ManagedContext {
        self.store_context.context_for(ContextType::Chain)
    }

    fn masternodes_context(&self) -> &ManagedContext {
        self.store_context.context_for(ContextType::Masternodes)
    }

    fn peer_context(&self) -> &ManagedContext {
        self.store_context.context_for(ContextType::Peer)
    }

    fn platform_context(&self) -> &ManagedContext {
        self.store_context.context_for(ContextType::Platform)
    }

    fn view_context(&self) -> &ManagedContext {
        self.store_context.context_for(ContextType::View)
    }
}
