use crate::storage::context_type::ContextType;
use crate::storage::manager::managed_context::ManagedContext;

#[derive(Clone, Debug)]
pub struct StoreContext {
    chain_context: ManagedContext,
    masternodes_context: ManagedContext,
    peer_context: ManagedContext,
    platform_context: ManagedContext,
    view_context: ManagedContext,
}
impl StoreContext {
    pub const fn new_const_default() -> Self {
        Self {
            chain_context: ManagedContext::new_const_default(),
            masternodes_context: ManagedContext::new_const_default(),
            peer_context: ManagedContext::new_const_default(),
            platform_context: ManagedContext::new_const_default(),
            view_context: ManagedContext::new_const_default()
        }
    }
}
impl Default for StoreContext {
    fn default() -> Self {
        Self::new_const_default()
    }
}

impl StoreContext {
    pub fn new() -> Self {
        Self::new_const_default()
    }
    pub fn context_for(&self, r#type: ContextType) -> &ManagedContext {
        match r#type {
            ContextType::View => &self.view_context,
            ContextType::Peer => &self.peer_context,
            ContextType::Chain => &self.chain_context,
            ContextType::Masternodes => &self.masternodes_context,
            ContextType::Platform => &self.platform_context
        }
    }

}
