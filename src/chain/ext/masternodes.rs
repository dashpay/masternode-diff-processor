use std::fmt::Debug;
use crate::chain::Chain;
use crate::chain::masternode::LocalMasternode;
use crate::chain::network::Peer;
use crate::chain::tx::ProviderRegistrationTransaction;
use crate::crypto::UInt128;
use crate::util::Shared;

pub trait ChainMasternodes {
    fn local_masternode_from_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction, save: bool) -> Option<&LocalMasternode>;
    fn has_masternode_at_location(&self, ip_address: UInt128, port: u16) -> bool;
}

pub trait PeerMasternodeDelegate: Sync + Debug {
    fn peer_relayed_masternode_diff_message(&self, peer: &Peer, message: &[u8]);
    fn peer_relayed_quorum_rotation_info_message(&self, peer: &Peer, message: &[u8]);
}

impl ChainMasternodes for Shared<Chain> {
    fn local_masternode_from_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction, save: bool) -> Option<&LocalMasternode> {
        todo!()
        //self.with(|chain| chain.masternode_manager.local_masternode_from_provider_registration_transaction(transaction, save))
    }

    fn has_masternode_at_location(&self, ip_address: UInt128, port: u16) -> bool {
        self.with(|chain| chain.masternode_manager.has_masternode_at_location(ip_address, port))
    }
}

impl PeerMasternodeDelegate for Shared<Chain> {
    fn peer_relayed_masternode_diff_message(&self, peer: &Peer, message: &[u8]) {
        todo!()
    }

    fn peer_relayed_quorum_rotation_info_message(&self, peer: &Peer, message: &[u8]) {
        todo!()
    }
}
