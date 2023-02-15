pub extern crate bitcoin_hashes as hashes;
use std::sync::{Arc, Mutex};
use dash_spv_masternode_processor::chains_manager::ChainsManager;
use dash_spv_masternode_processor::util::Shared;

fn main() {
    // will be an opaque_pointer for ffi
    let manager = Shared::Owned(Arc::new(Mutex::new(ChainsManager::new())));
}
