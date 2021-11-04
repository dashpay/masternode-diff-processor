use std::collections::HashMap;
use std::time::SystemTime;
use byte::{BytesExt, LE};
use crate::common::block_data::BlockData;
use crate::common::socket_address::SocketAddress;
use crate::crypto::byte_util::{Data, short_hex_string_from};
use crate::keys::key::Key;

pub const MN_ENTRY_PAYLOAD_LENGTH: usize = 151;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MasternodeEntry {
    pub provider_registration_transaction_hash: [u8; 32],
    pub confirmed_hash: [u8; 32],
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: Option<[u8; 32]>,
    pub socket_address: SocketAddress,
    pub operator_public_key: [u8; 48],

    pub previous_operator_public_keys: HashMap<BlockData, [u8; 48]>,
    pub previous_simplified_masternode_entry_hashes: HashMap<BlockData, [u8; 32]>,
    pub previous_validity: HashMap<BlockData, bool>,
    // pub previous_operator_public_keys: HashMap<(u32, [u8; 32]), [u8; 48]>,
    // pub previous_simplified_masternode_entry_hashes: HashMap<(u32, [u8; 32]), [u8; 32]>,
    // pub previous_validity: HashMap<(u32, [u8; 32]), bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub key_id_voting: [u8; 20],
    pub is_valid: bool,
    pub simplified_masternode_entry_hash: [u8; 32],
    pub platform_ping: Option<u64>,
    pub platform_ping_date: Option<SystemTime>,
}

impl MasternodeEntry {
    fn calculate_simplified_masternode_entry_hash(
        provider_registration_transaction_hash: [u8; 32],
        confirmed_hash: [u8; 32],
        socket_address: &SocketAddress,
        operator_public_key: [u8; 48],
        key_id_voting: [u8; 20],
        is_valid: u8,
    ) -> [u8; 32] {
        let offset: &mut usize = &mut 0;
        const HASH_IMPORTANT_DATA_LENGTH: i32 = 32 + 32 + 16 + 2 + 48 + 20 + 1;
        let mut hash_important_data = [0u8; HASH_IMPORTANT_DATA_LENGTH];
        hash_important_data.write(offset, provider_registration_transaction_hash);
        hash_important_data.write(offset, confirmed_hash);
        hash_important_data.write(offset, socket_address.ip_address);
        hash_important_data.write(offset, socket_address.port);
        hash_important_data.write(offset, operator_public_key);
        hash_important_data.write(offset, key_id_voting);
        hash_important_data.write(offset, is_valid);
        hash_important_data
    }

    pub fn confirmed_hash_at(&self, block_height: u32) -> [u8; 32] {
        if !self.known_confirmed_at_height {
            return self.confirmed_hash;
        }
        if self.known_confirmed_at_height > block_height {
            [0u8; 32]
        } else {
            self.confirmed_hash
        }
    }

    pub fn confirmed_hash_hashed_with_provider_registration_transaction_hash_at(&self, block_height: u32) -> Option<[u8; 32]> {
        if self.known_confirmed_at_height.is_none() || self.known_confirmed_at_height? <= block_height {
            self.confirmed_hash_hashed_with_provider_registration_transaction_hash
        } else {
            MasternodeEntry::hash_confirmed_hash(&[0u8; 32], &self.provider_registration_transaction_hash);
        }
    }

    pub fn set_platform_ping(&mut self, ping: Option<u64>, ping_date: Option<SystemTime>) {
        self.platform_ping = ping;
        self.platform_ping_date = ping_date;
    }

    pub fn host(&self) -> &str {
        let ip = self.socket_address.ip_address;
        let port = self.socket_address.port;
        &format!("{}:{}", &ip.to_string(), &port.to_string())
    }

    pub fn payload_data(&self) -> [u8; 32] {
        MasternodeEntry::calculate_simplified_masternode_entry_hash(
            self.provider_registration_transaction_hash,
            self.confirmed_hash,
            &self.socket_address,
            self.operator_public_key,
            self.key_id_voting,
            if self.is_valid {1} else {0}
        )
    }

    pub fn hash_confirmed_hash(confirmed_hash:&[u8; 32], pro_reg_tx_hash: &[u8; 32]) -> &[u8; 32] {
        let offset: &mut usize = &mut 0;
        let mut combined_data = [0u8; 64];
        combined_data.write(offset, confirmed_hash);
        combined_data.write(offset, pro_reg_tx_hash);
        let mut hasher = Sha256::new();
        hasher.update(combined_data);
        hasher.finalize()
    }

    pub fn is_valid_at(&self, block_height: u32) -> bool {
        if self.previous_validity.len() == 0 || block_height == u32::MAX {
            return self.is_valid;
        }
        let mut min_distance = u32::MAX;
        let mut is_valid = self.is_valid;
        for (previous_block, validity) in self.previous_validity {
            let previous_block_height = previous_block.height;
            let distance = previous_block_height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                println("Validity for proTxHash {} : Using {} instead of {} for list at block height {} (previousBlock.height {})", self.provider_registration_transaction_hash, self.previous_validity[previous_block], is_valid, block_height, previous_block_height);
                is_valid = validity;
            }
        }
        is_valid
    }

    pub fn operator_public_key_at(&self, block_height: u32) -> &[u8; 48] {
        if self.previous_operator_public_keys.is_empty() {
            return &self.operator_public_key;
        }
        let mut min_distance = u32::MAX;
        let mut used_previous_operator_public_key_at_block_hash = self.operator_public_key;
        for block in self.previous_operator_public_keys {
            let prev_block_height = block.height;
            let distance = prev_block_height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                used_previous_operator_public_key_at_block_hash = block.hash;
            }
        }
        &used_previous_operator_public_key_at_block_hash
    }


    pub fn keep_info_of_previous_entry_version(&mut self, mut masternode_entry: MasternodeEntry, block_height: u32, block_hash: [u8; 32]) {
        if self.provider_registration_transaction_hash == masternode_entry.provider_registration_transaction_hash {
            self.previous_validity = HashMap::new();
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have previousValidity that is
            // in our future we need to ignore them
            for ((height, hash), validity) in masternode_entry.previous_validity {
                if height < self.update_height {
                    self.previous_validity[(height, hash)] = validity;
                }
            }
            if masternode_entry.is_valid_at(self.update_height) != self.is_valid {
                println!("Changed validity from {} to {} on {:?}", masternode_entry.is_valid, self.is_valid, self.provider_registration_transaction_hash);
                self.previous_validity[block_height] = masternode_entry.is_valid;
            }
            self.previous_operator_public_keys = HashMap::new();
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have previousOperatorPublicKeys
            // that is in our future we need to ignore them
            for ((height, hash), key) in masternode_entry.previous_operator_public_keys {
                if height < self.update_height {
                    self.previous_operator_public_keys[(height, hash)] = key;
                }
            }
            if masternode_entry.operator_public_key_at(self.update_height) != self.operator_public_key {
                // the operator public key changed
                println!("Changed sme operator keys from {:?} to {:?} on {:?}", masternode_entry.operator_public_key, self.operator_public_key, self.provider_registration_transaction_hash);
                self.previous_operator_public_keys[block_height] = masternode_entry.operator_public_key;
            }
            self.previous_simplified_masternode_entry_hashes = HashMap::new();
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have
            // previousSimplifiedMasternodeEntryHashes that is in our future we need to ignore them
            for ((height, hash), entry_hash) in masternode_entry.previous_simplified_masternode_entry_hashes {
                if height < self.update_height {
                    self.previous_simplified_masternode_entry_hashes[(height, hash)] = entry_hash;
                }
            }
            if masternode_entry.simplified_masternode_entry_hash_at(self.update_height) != self.simplified_masternode_entry_hash {
                // the hashes changed
                println!("Changed sme hashes from {:?} to {:?} on {:?}", masternode_entry.simplified_masternode_entry_hash, self.simplified_masternode_entry_hash, self.provider_registration_transaction_hash);
                self.previous_simplified_masternode_entry_hashes[(block_height, block_hash)] = masternode_entry.simplified_masternode_entry_hash;
            }
        }
        // if the masternodeEntry.confirmedHash is not set we do not need to do anything the
        // knownConfirmedHashAtHeight will be higher and if the masternodeEntry.confirmedHash is
        // set we might need to update our knownConfirmedAtHeight
        if !masternode_entry.confirmed_hash.is_empty() && masternode_entry.known_confirmed_at_height? > block_height {
            // we found it confirmed at a previous height
            masternode_entry.known_confirmed_at_height = Some(block_height);
        }
    }

    pub fn simplified_masternode_entry_hash_at(&self, block_height: u32) -> [u8; 32] {
        if self.previous_simplified_masternode_entry_hashes.len() == 0 {
            self.simplified_masternode_entry_hash
        }
        if block_height == u32::MAX {
            println!("block height should be set");
            return self.simplified_masternode_entry_hash;
        }
        let hashes: HashMap<BlockData, [u8; 32]> = self.previous_simplified_masternode_entry_hashes.clone();
        // let hashes: HashMap<(u32, [u8; 32]), [u8; 32]> = self.previous_simplified_masternode_entry_hashes.clone();
        let mut min_distance = u32::MAX;
        let mut used_hash = self.simplified_masternode_entry_hash;
        for (block, hash) in hashes {
            let distance = block.height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                used_hash = hash;
            }
        }
        used_hash
    }


    pub fn unique_id(&self) -> &str {
        short_hex_string_from(&*self.provider_registration_transaction_hash)
    }

    pub fn new(message: &[u8; MN_ENTRY_PAYLOAD_LENGTH], block_height: u32) -> MasternodeEntry {
        let length = message.len();
        let offset = &mut 0;
        assert!(length - offset >= 32);
        let provider_registration_transaction_hash = message.read_with::<[u8; 32]>(offset, LE)?;
        assert!(length - offset >= 32);
        let confirmed_hash = message.read_with::<[u8; 32]>(offset, LE)?;
        let known_confirmed_at_height: Option<u32> =
            if confirmed_hash != 0 && block_height != u32::MAX {
                Some(block_height)
            } else {
                None
            };
        assert!(length - offset >= 16);
        let ip_address = message.read_with::<u128>(offset, LE)?;
        assert!(length - offset >= 2);
        let port = message.read_with::<u16>(offset, LE)?;
        let socket_address = SocketAddress { ip_address, port };
        assert!(length - offset >= 48);
        let operator_public_key = message.read_with::<[u8; 48]>(offset, LE)?;
        assert!(length - offset >= 20);
        let key_id_voting = message.read_with::<[u8; 20]>(offset, LE)?;
        assert!(length - offset >= 1);
        let is_valid = message.read_with::<u8>(offset, LE)?;
        let simplified_masternode_entry_hash = MasternodeEntry::calculate_simplified_masternode_entry_hash(
            provider_registration_transaction_hash,
            confirmed_hash,
            &socket_address,
            operator_public_key,
            key_id_voting,
            is_valid
        );
        MasternodeEntry {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: None,
            socket_address,
            operator_public_key,
            previous_operator_public_keys: HashMap::new(),
            previous_simplified_masternode_entry_hashes: HashMap::new(),
            previous_validity: HashMap::new(),
            known_confirmed_at_height,
            update_height: block_height,
            key_id_voting,
            is_valid: is_valid != 0,
            simplified_masternode_entry_hash,
            platform_ping: None,
            platform_ping_date: None
        }
    }
}


