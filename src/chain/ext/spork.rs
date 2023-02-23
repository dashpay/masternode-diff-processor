use crate::chain::Chain;
use crate::chain::network::Peer;
use crate::chain::spork::manager::PeerSporkDelegate;
use crate::chain::spork::Spork;
use crate::UInt256;
use crate::util::Shared;

impl PeerSporkDelegate for Shared<Chain> {
    fn peer_relayed_spork(&mut self, peer: &mut Peer, spork: Spork) {
        self.with(|chain| chain.spork_manager.peer_relayed_spork(peer, spork))
    }

    fn peer_has_spork_hashes(&mut self, peer: &Peer, hashes: Vec<UInt256>) {
        self.with(|chain| chain.spork_manager.peer_has_spork_hashes(peer, hashes))
    }
}
