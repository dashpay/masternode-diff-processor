use std::collections::HashMap;
use std::time::SystemTime;
use crate::chain::common::chain_type::{DevnetType, IHaveChainSettings};
use crate::chain::ext::{Derivation, Settings};
use crate::chain::params::{create_devnet_params_for_type, MAINNET_PARAMS, Params, TESTNET_PARAMS};
use crate::chain::{spork, SyncPhase, SyncType, Wallet};
use crate::chain::options::Options;
use crate::chain::spork::Spork;
use crate::{default_shared, UInt256};
use crate::chain::block::Block;
use crate::chain::network::Peer;
use crate::chain::wallet::Account;
use crate::chain::wallet::ext::constants::BIP39_CREATION_TIME;
use crate::chain::wallet::seed::Seed;
use crate::derivation::{DerivationPath, DerivationPathKind};
use crate::derivation::factory::Factory;
use crate::manager::authentication_manager::AuthenticationManager;
use crate::manager::masternode_manager::MasternodeManager;
use crate::manager::PeerManager;
use crate::manager::transaction_manager::TransactionManager;
use crate::storage::context::StoreContext;
use crate::storage::{Keychain, UserDefaults};
use crate::util::shared::{Shareable, Shared};
use crate::util::TimeUtil;

#[derive(Clone, Debug, Default)]
pub struct Chain {
    pub params: Params,
    pub wallets: Vec<Wallet>,
    pub store_context: StoreContext,
    pub derivation_factory: Factory,

    pub last_sync_block: Option<Block>,
    pub last_terminal_block: Option<Block>,
    pub terminal_blocks: HashMap<UInt256, Block>,
    pub sync_blocks: HashMap<UInt256, Block>,

    pub authentication_manager: Shared<AuthenticationManager>,
    pub masternode_manager: MasternodeManager,
    pub peer_manager: PeerManager,
    pub spork_manager: spork::Manager,
    pub transaction_manager: TransactionManager,
    pub options: Options,
    pub sync_phase: SyncPhase,
    viewing_account: Option<Account>,

    // pub network_context: NetworkContext,


    pub chain_sync_start_height: u32,
    pub terminal_sync_start_height: u32,

}

impl Shareable for Chain {}

default_shared!(Chain);
default_shared!(Vec<Wallet>);

// impl PartialEq for Shared<Chain> {
//     fn eq(&self, other: &Self) -> bool {
//         self.with(|chain| chain).eq(&other.with(|chain| chain))
//     }
// }

// impl<'a> Default for &'a Chain<'a> {
//     fn default() -> &'a Chain<'a> {
//         static VALUE: Chain = Chain {
//             params: MAINNET_PARAMS,
//             wallets: vec![],
//             store_context: StoreContext::new_const_default(),
//             derivation_factory: Factory::new_const_default(),
//             // environment: Environment::new_const_default(),
//         };
//         &VALUE
//     }
// }

impl PartialEq<Self> for Chain {
    fn eq(&self, other: &Self) -> bool {
        self == other || other.r#type().genesis_hash().eq(&self.r#type().genesis_hash())
    }
}

impl Eq for Chain {}

/// Managers
impl Shared<Chain> {
    pub fn setup(&self) {
        self.restore_wallets_and_standalone_derivation_paths();
    }


    // pub fn spork_manager(&self) -> spork::Manager {
    //     self.with(|chain| chain.spork_manager)
    // }
    // pub fn peer_manager(&self) -> PeerManager {
    //     self.with(|chain| chain.peer_manager)
    // }
    /// required for SPV wallets
    pub fn syncs_blockchain(&self) -> bool {
        self.with(|chain| chain.options.sync_type.bits() & SyncType::NeedsWalletSyncType.bits() == 0)
        // self.options.sync_type.bits() & SyncType::NeedsWalletSyncType.bits() == 0
        // !(self.options.sync_type & SyncType::NeedsWalletSyncType)
    }
    pub fn send_filter_if_need(&self, peer: &mut Peer) {
        self.with(|chain| if chain.syncs_blockchain() && chain.can_construct_a_filter() {
            peer.send_filterload_message(chain.transaction_manager.transactions_bloom_filter_for_peer_hash(peer.hash()).to_data());
        });
    }

    pub fn can_construct_a_filter(&self) -> bool {
        self.with(|chain| chain.can_construct_a_filter())
    }

    pub fn should_continue_sync_blockchain_after_height(&self, height: u32) -> bool {
        self.with(|chain| chain.syncs_blockchain() &&
            (chain.last_sync_block_height() != chain.last_terminal_block_height()) ||
            chain.last_sync_block_height() < height)
    }

    pub fn restore_wallets_and_standalone_derivation_paths(&self) {
        self.with(|chain| {
            match Keychain::get_array::<String>(chain.r#type().chain_wallets_key(), vec![]) {
                Ok(wallet_ids) => {
                    wallet_ids.into_iter().for_each(|wallet_id| {
                        chain.add_wallet(Wallet::init_with_chain_and_unique_id(wallet_id, false, self.borrow()));
                    });
                    // we should load identities after all wallets are in the chain, as identities
                    // might be on different wallets and have interactions between each other
                    chain.wallets.iter().for_each(|wallet| wallet.load_identities());
                },
                Err(err) => println!("Error restoring wallets {:?}", err)
            }
            match Keychain::get_array::<String>(chain.r#type().chain_standalone_derivation_paths_key(), vec![]) {
                Ok(derivation_path_ids) => {
                    derivation_path_ids.into_iter().for_each(|derivation_path_id| {
                        if let Some(path) = DerivationPath::init_with_extended_public_key_identifier(derivation_path_id.as_str(), chain.r#type(), self.borrow()) {
                            chain.add_standalone_derivation_path(DerivationPathKind::Default(path));
                        }
                    });
                },
                Err(err) => println!("Error restoring standalone derivation paths {:?}", err)
            }
        });
    }


}
impl Chain {
    fn create(params: Params) -> Shared<Self> {
        let chain_type = params.chain_type.clone();
        let chain = Self {
            params,
            store_context: StoreContext::new(),
            derivation_factory: Factory::new(),
            authentication_manager: Default::default(),
            masternode_manager: MasternodeManager::new(chain_type),
            peer_manager: PeerManager::new(chain_type),
            spork_manager: spork::Manager::new(chain_type),
            transaction_manager: TransactionManager::new(chain_type),
            // network_context: NetworkContext::new(),
            ..Default::default()
        }.to_shared();
        chain.with(|c| {
            c.masternode_manager.chain = chain.borrow();
            c.peer_manager.chain = chain.borrow();
            c.spork_manager.chain = chain.borrow();
            c.transaction_manager.chain = chain.borrow();
        });
        chain
    }
    pub fn create_mainnet() -> Shared<Self> {
        Self::create(MAINNET_PARAMS)
    }

    pub fn create_testnet() -> Shared<Self> {
        Self::create(TESTNET_PARAMS)
    }

    pub fn create_devnet(r#type: DevnetType) -> Shared<Self> {
        Self::create(create_devnet_params_for_type(r#type))
    }
}

impl Chain {


    pub fn start_sync(&mut self) {
        // dispatch_async(dispatch_get_main_queue(), ^{
        //     [[NSNotificationCenter defaultCenter] postNotificationName:DSChainManagerSyncWillStartNotification
        //     object:nil
        //     userInfo:@{DSChainManagerNotificationChainKey: self.chain}];
        // });
        self.peer_manager.connect()
    }

}

impl Chain {
    pub fn add_wallet(&mut self, wallet: Wallet) -> bool {
        let not_present_yet = self.wallets.iter().find(|w| wallet.unique_id_string() == w.unique_id_string()).is_none();
        if not_present_yet {
            self.wallets.push(wallet);
        }
        not_present_yet
    }

    pub fn add_standalone_derivation_path(&mut self, path: DerivationPathKind) {
        if let Some(mut acc) = self.viewing_account.take() {
            acc.add_derivation_path(path);
        } else {
            let mut acc = Account::view_only_account_with_number(0);
            acc.add_derivation_path(path);
            self.viewing_account = Some(acc);
        }
    }
    pub fn last_sync_block_height(&mut self) -> u32 {
        todo!()
        // self.last_terminal_block().unwrap().height()
    }

    pub fn last_terminal_block_height(&mut self) -> u32 {
        todo!()
        // self.last_terminal_block().unwrap().height()
    }

    pub fn should_request_merkle_blocks_for_next_sync_block_height(&mut self) -> bool {
        todo!()
        // self.should_request_merkle_blocks_for_zone_after_height(self.last_sync_block_height() + 1)
    }

    pub fn should_request_merkle_blocks_for_zone_after_height(&mut self, block_height: u32) -> bool {
        todo!()
        // let block_zone: u16 = (block_height / 500) as u16;
        // let left_over: u16 = (block_height % 500) as u16;
        // if self.chain_synchronization_fingerprint.is_some() {
        //     self.chain_synchronization_block_zones().contains(&block_zone) ||
        //         self.chain_synchronization_block_zones().contains(&(block_zone + 1)) ||
        //         self.chain_synchronization_block_zones().contains(&(block_zone + 2)) ||
        //         self.chain_synchronization_block_zones().contains(&(block_zone + 3)) ||
        //         (left_over == 0 && self.should_request_merkle_blocks_for_zone_after_height(((block_zone + 1) * 500) as u32))
        // } else {
        //     true
        // }
    }
    pub fn set_estimated_block_height(&mut self, height: u32, peer: &Peer, threshold_peer_count: usize) {
        todo!()
    }

    pub fn estimated_block_height(&mut self) -> u32 {
        todo!()
        // if let Some(bebh) = self.best_estimated_block_height {
        //     bebh
        // } else {
        //     let bebh = self.decide_from_peer_soft_consensus_estimated_block_height();
        //     self.best_estimated_block_height = Some(bebh);
        //     bebh
        // }
    }

    pub fn needs_initial_terminal_headers_sync(&mut self) -> bool {
        self.estimated_block_height() != self.last_terminal_block_height()
    }

    pub fn chain_sync_block_locator_array(&mut self) -> Vec<UInt256> {
        todo!()
        // if self.last_sync_block.is_some() && self.last_sync_block.unwrap().height() == 1 && self.is_devnet_any() {
        //     self.block_locator_array_for_block(self.last_sync_block)
        // } else if let Some(locators) = &self.last_persisted_chain_info.locators {
        //     locators.clone()
        // } else {
        //     let locators: Vec<UInt256> = self.block_locator_array_on_or_before_timestamp(BIP39_CREATION_TIME, false);
        //     self.last_persisted_chain_info.locators = Some(locators);
        //     locators.clone()
        // }
    }
    pub fn syncs_blockchain(&self) -> bool {
        self.options.sync_type.bits() & SyncType::NeedsWalletSyncType.bits() == 0
    }

    pub fn can_construct_a_filter(&mut self) -> bool {
        todo!()
        // self.has_a_standalone_derivation_path() || self.has_a_wallet()
    }

    /// This is a time interval since 1970
    pub fn earliest_wallet_creation_time(&self) -> u64 {
        self.wallets.iter()
            .map(|wallet| wallet.wallet_creation_time())
            .min_by(|t1, t2| t1.cmp(t2))
            .unwrap_or(BIP39_CREATION_TIME as u64)
    }

    pub fn reset_chain_sync_start_height(&mut self) {
        let key = self.params.chain_type.chain_sync_start_height_key();
        if self.chain_sync_start_height == 0 {
            self.chain_sync_start_height = UserDefaults::get::<u32>(key.as_str()).unwrap_or(0);
        }
        if self.chain_sync_start_height == 0 {
            self.chain_sync_start_height = self.last_sync_block_height();
            UserDefaults::set(key.as_str(), self.chain_sync_start_height);
        }
    }

    pub fn restart_chain_sync_start_height(&mut self) {
        self.chain_sync_start_height = 0;
        UserDefaults::set(self.params.chain_type.chain_sync_start_height_key().as_str(), 0u32);
    }

    pub fn reset_terminal_sync_start_height(&mut self) {
        let key = self.params.chain_type.terminal_sync_start_height_key();
        if self.terminal_sync_start_height == 0 {
            self.terminal_sync_start_height = UserDefaults::get::<u32>(key.as_str()).unwrap_or(0);
        }
        if self.terminal_sync_start_height == 0 {
            self.terminal_sync_start_height = self.last_terminal_block_height();
            UserDefaults::set(key.as_str(), self.terminal_sync_start_height);
        }
    }

    pub fn restart_chain_terminal_sync_start_height(&mut self) {
        self.terminal_sync_start_height = 0;
        UserDefaults::set(self.params.chain_type.terminal_sync_start_height_key().as_str(), 0u32);
    }

}

impl Shared<Chain> {
    pub fn is_spork_activated(&self, spork: &Spork) -> bool {
        self.with(|chain| spork.value <= chain.last_terminal_block_height() as u64)
    }

    pub fn should_request_merkle_blocks_for_zone_after_last_sync_height(&self) -> bool {
        self.with(|chain|
            !chain.needs_initial_terminal_headers_sync() &&
            chain.should_request_merkle_blocks_for_next_sync_block_height())
    }

    pub fn remove_estimated_block_heights_of_peer(&mut self, peer: &Peer) {
        // for (height, mut announcers) in self.estimated_block_heights {
        //     if let Some(pos) = announcers.iter().position(|x| x == peer) {
        //         announcers.remove(pos);
        //     }
        //     if announcers.is_empty() {
        //         self.estimated_block_heights.remove_entry(&height);
        //     }
        //     // keep best estimate if no other peers reporting on estimate
        //     if !self.estimated_block_heights.is_empty() && height == self.best_estimated_block_height.unwrap() {
        //         self.best_estimated_block_height = Some(0);
        //     }
        // }
    }
    pub fn reset_last_relayed_item_time(&self) {
        //self.last_chain_relay_time = 0;
    }

    pub fn start_with_seed_phrase<L: bip0039::Language>(&self, seed_phrase: &str) {
        self.with(|chain| {
            match Seed::from_phrase::<L>(seed_phrase, chain.genesis()) {
                Some(seed) => {
                    match Keychain::save_seed_phrase(seed_phrase, SystemTime::seconds_since_1970(), seed.unique_id_as_str())
                        .ok()
                        .map(|()| {
                            self.register_derivation_paths_for_seed(&seed, chain.r#type());
                            Wallet::standard_wallet_with_seed(
                                seed,
                                0,
                                true,
                                chain.r#type(),
                                self.borrow())
                        }) {
                        Some(wallet) => {
                            chain.start_sync();
                        },
                        _ => {},
                    }

                },
                _ => {}
            }
        });
    }

}
