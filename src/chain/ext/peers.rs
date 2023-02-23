use crate::chain::{Chain, SyncCountInfo};
use crate::chain::network::Peer;
use crate::util::Shared;

pub trait PeerChainDelegate {
    fn peer_relayed_sync_info(&self, peer: &Peer, sync_count_info: &SyncCountInfo, count: u32);
    fn chain_finished_syncing_transactions_and_blocks(&mut self, peer: Option<&Peer>, on_main_chain: bool);
}

impl PeerChainDelegate for Shared<Chain> {
    fn peer_relayed_sync_info(&self, peer: &Peer, sync_count_info: &SyncCountInfo, count: u32) {
        todo!()
    }

    fn chain_finished_syncing_transactions_and_blocks(&mut self, peer: Option<&Peer>, on_main_chain: bool) {
        todo!()
    }
}
