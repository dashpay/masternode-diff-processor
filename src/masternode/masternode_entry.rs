use std::collections::{BTreeMap, HashMap};
use byte::{BytesExt, LE};
use crate::common::block_data::BlockData;
use crate::common::socket_address::SocketAddress;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{MNPayload, short_hex_string_from, UInt128, UInt160, UInt256, UInt384};
use crate::hashes::{Hash, sha256, sha256d};

// #[repr(C)]
#[derive(Clone, Debug)]
pub struct MasternodeEntry {
    pub provider_registration_transaction_hash: UInt256,
    pub confirmed_hash: UInt256,
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: Option<UInt256>,
    pub socket_address: SocketAddress,
    pub operator_public_key: UInt384,
    pub previous_operator_public_keys: BTreeMap<BlockData, UInt384>,
    pub previous_masternode_entry_hashes: HashMap<BlockData, UInt256>,
    pub previous_validity: HashMap<BlockData, bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub key_id_voting: UInt160,
    pub is_valid: bool,
    pub masternode_entry_hash: UInt256,
}

impl MasternodeEntry {
    fn calculate_masternode_entry_hash(
        provider_registration_transaction_hash: UInt256,
        confirmed_hash: UInt256,
        socket_address: SocketAddress,
        operator_public_key: UInt384,
        key_id_voting: UInt160,
        is_valid: u8,
    ) -> UInt256 {
        let offset: &mut usize = &mut 0;
        const HASH_IMPORTANT_DATA_LENGTH: usize = 32 + 32 + 16 + 2 + 48 + 20 + 1;
        let mut buffer: Vec<u8> = Vec::with_capacity(HASH_IMPORTANT_DATA_LENGTH);
        *offset += provider_registration_transaction_hash.consensus_encode(&mut buffer).unwrap();
        *offset += confirmed_hash.consensus_encode(&mut buffer).unwrap();
        *offset += socket_address.ip_address.consensus_encode(&mut buffer).unwrap();
        *offset += socket_address.port.consensus_encode(&mut buffer).unwrap();
        *offset += operator_public_key.consensus_encode(&mut buffer).unwrap();
        *offset += key_id_voting.consensus_encode(&mut buffer).unwrap();
        *offset += is_valid.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn confirmed_hash_at(&self, block_height: u32) -> Option<UInt256> {
        if self.known_confirmed_at_height.is_some() &&
            self.known_confirmed_at_height.unwrap() > block_height {
            None
        } else {
            Some(self.confirmed_hash)
        }
    }

    pub fn confirmed_hash_hashed_with_provider_registration_transaction_hash_at(&self, block_height: u32) -> Option<UInt256> {
        if self.known_confirmed_at_height.is_none() ||
            self.known_confirmed_at_height? <= block_height {
            self.confirmed_hash_hashed_with_provider_registration_transaction_hash
        } else {
            Some(MasternodeEntry::hash_confirmed_hash(UInt256::default(), self.provider_registration_transaction_hash))
        }
    }

    pub fn host(&self) -> String {
        let ip = self.socket_address.ip_address;
        let port = self.socket_address.port;
        format!("{}:{}", ip.to_string(), port.to_string())
    }

    pub fn payload_data(&self) -> UInt256 {
        MasternodeEntry::calculate_masternode_entry_hash(
            self.provider_registration_transaction_hash,
            self.confirmed_hash,
            self.socket_address,
            self.operator_public_key,
            self.key_id_voting,
            if self.is_valid {1} else {0}
        )
    }

    pub fn hash_confirmed_hash(confirmed_hash: UInt256, pro_reg_tx_hash: UInt256) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(64);
        let offset: &mut usize = &mut 0;
        *offset += pro_reg_tx_hash.consensus_encode(&mut buffer).unwrap();
        *offset += confirmed_hash.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256::Hash::hash(&buffer).into_inner())
    }

    pub fn is_valid_at(&self, block_height: u32) -> bool {
        if self.previous_validity.len() == 0 || block_height == u32::MAX {
            return self.is_valid;
        }
        let mut min_distance = u32::MAX;
        let mut is_valid = self.is_valid;
        for (BlockData { height, .. }, validity) in self.previous_validity.clone() {
            let distance = height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                is_valid = validity;
            }
        }
        is_valid
    }

    pub fn operator_public_key_at(&self, block_height: u32) -> UInt384 {
        if self.previous_operator_public_keys.is_empty() {
            return self.operator_public_key;
        }
        let mut min_distance = u32::MAX;
        let mut used_previous_operator_public_key_at_block_hash = self.operator_public_key;
        for (block, key) in self.previous_operator_public_keys.clone() {
            let prev_block_height = block.height;
            let distance = prev_block_height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                used_previous_operator_public_key_at_block_hash = key;
            }
        }
        used_previous_operator_public_key_at_block_hash
    }


    pub fn keep_info_of_previous_entry_version(&mut self, mut masternode_entry: MasternodeEntry, block_height: u32, block_hash: UInt256) {
        let b = BlockData { height: block_height, hash: block_hash };
        if self.provider_registration_transaction_hash == masternode_entry.provider_registration_transaction_hash {
            // self.previous_validity = HashMap::new();
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have previousValidity that is
            // in our future we need to ignore them

            self.previous_validity = masternode_entry
                .clone()
                .previous_validity
                .into_iter()
                .filter(|(block, _)| block.height < self.update_height)
                .collect();

            if masternode_entry.is_valid_at(self.update_height) != self.is_valid {
                println!("Changed validity from {} to {} on {:?}", masternode_entry.is_valid, self.is_valid, self.provider_registration_transaction_hash);
                self.previous_validity.insert(b, masternode_entry.is_valid);
            }
            self.previous_operator_public_keys = BTreeMap::new();
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have previousOperatorPublicKeys
            // that is in our future we need to ignore them
            for (block, key) in &masternode_entry.previous_operator_public_keys {
                if block.height < self.update_height {
                    self.previous_operator_public_keys.insert(*block, *key);
                }
            }
            if masternode_entry.operator_public_key_at(self.update_height) != self.operator_public_key {
                // the operator public key changed
                println!("Changed sme operator keys from {:?} to {:?} on {:?}", masternode_entry.operator_public_key, self.operator_public_key, self.provider_registration_transaction_hash);
                self.previous_operator_public_keys.insert(b, masternode_entry.operator_public_key);
            }
            // if for example we are getting a masternode list at block 402 when we already got the
            // masternode list at block 414 then the other sme might have
            // previous_masternode_entry_hashes that is in our future we need to ignore them

            self.previous_masternode_entry_hashes = masternode_entry
                .clone()
                .previous_masternode_entry_hashes
                .into_iter()
                .filter(|(block, _hash)| block.height < self.update_height)
                .collect();

            let hash_for_height = masternode_entry.masternode_entry_hash_at(self.update_height);
            if hash_for_height != self.masternode_entry_hash {
                // the hashes changed
                println!("Changed sme hashes from {:?} to {:?} on {:?}", masternode_entry.masternode_entry_hash, self.masternode_entry_hash, self.provider_registration_transaction_hash);
                self.previous_masternode_entry_hashes.insert(b, masternode_entry.masternode_entry_hash);
            }
        }
        // if the masternodeEntry.confirmedHash is not set we do not need to do anything the
        // knownConfirmedHashAtHeight will be higher and if the masternodeEntry.confirmedHash is
        // set we might need to update our knownConfirmedAtHeight
        if !masternode_entry.confirmed_hash.0.is_empty() &&
            masternode_entry.known_confirmed_at_height.unwrap() > block_height {
            // we found it confirmed at a previous height
            masternode_entry.known_confirmed_at_height = Some(block_height);
        }
    }

    pub fn masternode_entry_hash_at(&self, block_height: u32) -> UInt256 {
        if self.previous_masternode_entry_hashes.len() == 0 ||
            block_height == u32::MAX {
            return self.masternode_entry_hash;
        }
        let hashes: HashMap<BlockData, UInt256> = self.previous_masternode_entry_hashes.clone();
        let mut min_distance = u32::MAX;
        let mut used_hash = self.masternode_entry_hash;
        for (BlockData { height, .. }, hash) in hashes {
            let distance = height - block_height;
            if (1..min_distance).contains(&distance) {
                min_distance = distance;
                used_hash = hash;
            }
        }
        used_hash
    }


    pub fn unique_id(&self) -> String {
        short_hex_string_from(&self.provider_registration_transaction_hash.0)
    }

    pub fn new(message: MNPayload, block_height: u32) -> Option<MasternodeEntry> {
        // let length = message.len();
        let message = message.0;
        let offset = &mut 0;
        let provider_registration_transaction_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let confirmed_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let known_confirmed_at_height: Option<u32> =
            if confirmed_hash.0.is_empty() &&
                block_height != u32::MAX {
                Some(block_height)
            } else {
                None
            };
        let ip_address = match message.read_with::<UInt128>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let port = match message.read_with::<u16>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = match message.read_with::<UInt384>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let key_id_voting = match message.read_with::<UInt160>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return None; }
        };
        let is_valid = match message.read_with::<u8>(offset, LE) {
            Ok(data) => data,
            Err(_err) => 0
        };
        let masternode_entry_hash = MasternodeEntry::calculate_masternode_entry_hash(
            provider_registration_transaction_hash,
            confirmed_hash,
            socket_address,
            operator_public_key,
            key_id_voting,
            is_valid
        );
        Some(MasternodeEntry {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: None,
            socket_address,
            operator_public_key,
            previous_operator_public_keys: BTreeMap::new(),
            previous_masternode_entry_hashes: HashMap::new(),
            previous_validity: HashMap::new(),
            known_confirmed_at_height,
            update_height: block_height,
            key_id_voting,
            is_valid: is_valid != 0,
            masternode_entry_hash
        })
    }
}
