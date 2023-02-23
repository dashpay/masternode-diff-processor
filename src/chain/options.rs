use crate::chain::SyncType;
use crate::storage::UserDefaults;

#[derive(Clone, Debug)]
pub struct Options {
    pub keep_headers: bool,
    pub use_checkpoint_masternode_lists: bool,
    pub smart_outputs: bool,
    pub sync_from_genesis: bool,
    pub retrieve_price_info: bool,
    pub should_sync_from_height: bool,
    pub should_use_checkpoint_file: bool,
    pub sync_from_height: u32,
    pub sync_governance_objects_interval: u64, //NSTimeInterval
    pub sync_masternode_list_interval: u64, //NSTimeInterval
    pub sync_type: SyncType,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            keep_headers: false,
            use_checkpoint_masternode_lists: true,
            smart_outputs: true,
            sync_from_genesis: false,
            retrieve_price_info: true,
            should_sync_from_height: false,
            should_use_checkpoint_file: true,
            sync_from_height: 0,
            sync_governance_objects_interval: 600, // 10 min
            sync_masternode_list_interval: 600, // 10 min
            sync_type: SyncType::Default
        }
    }
}

impl Options {

    pub fn set_sync_from_genesis(&mut self, sync_from_genesis: bool) {
        if sync_from_genesis {
            self.sync_from_height = 0;
            self.should_sync_from_height = true;
        } else if let Some(sync_from_height) = UserDefaults::object_for_key::<u32>("syncFromHeight") {
            if self.sync_from_height == 0 {
                UserDefaults::remove_object_for_key("syncFromHeight");
                self.should_sync_from_height = false;
            }
        }
    }

    pub fn add_sync_type(&mut self, sync_type: SyncType) {
        self.sync_type = self.sync_type.clone() | sync_type;
    }
    pub fn clear_sync_type(&mut self, sync_type: SyncType) {
        self.sync_type = self.sync_type.clone() & !sync_type;
    }

    pub fn sync_from_genesis(&self) -> bool {
        if UserDefaults::has_key("syncFromHeight") {
            self.sync_from_height == 0 && self.should_sync_from_height
        } else {
            false
        }
        // UserDefaults::object_for_key::<u32>("syncFromHeight")
        //     .map_or(false, self.sync_from_height == 0 && self.should_sync_from_height)

    }

}
