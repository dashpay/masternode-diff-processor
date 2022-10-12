use crate::common::Block;
use crate::common::SocketAddress;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use dash_spv_primitives::consensus::Encodable;
use dash_spv_primitives::crypto::byte_util::Zeroable;
use dash_spv_primitives::crypto::data_ops::short_hex_string_from;
use dash_spv_primitives::crypto::{UInt128, UInt160, UInt256, UInt384};
use dash_spv_primitives::hashes::{sha256, sha256d, Hash};
use std::collections::BTreeMap;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct MasternodeEntry {
    pub provider_registration_transaction_hash: UInt256,
    pub confirmed_hash: UInt256,
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: Option<UInt256>,
    pub socket_address: SocketAddress,
    pub operator_public_key: UInt384,
    pub previous_operator_public_keys: BTreeMap<Block, UInt384>,
    pub previous_entry_hashes: BTreeMap<Block, UInt256>,
    pub previous_validity: BTreeMap<Block, bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub key_id_voting: UInt160,
    pub is_valid: bool,
    pub entry_hash: UInt256,
}
impl std::fmt::Debug for MasternodeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeEntry")
            .field(
                "provider_registration_transaction_hash",
                &self.provider_registration_transaction_hash,
            )
            // .field("confirmed_hash", &self.confirmed_hash)
            // .field("confirmed_hash_hashed_with_provider_registration_transaction_hash", &self.confirmed_hash_hashed_with_provider_registration_transaction_hash)
            // .field("socket_address", &self.socket_address)
            // .field("operator_public_key", &self.operator_public_key)
            // .field("previous_operator_public_keys", &self.previous_operator_public_keys)
            // .field("previous_entry_hashes", &self.previous_entry_hashes)
            // .field("previous_validity", &self.previous_validity)
            // .field("known_confirmed_at_height", &self.known_confirmed_at_height)
            // .field("update_height", &self.update_height)
            // .field("key_id_voting", &self.key_id_voting)
            // .field("is_valid", &self.is_valid)
            // .field("entry_hash", &self.entry_hash)
            .finish()
    }
}
impl<'a> TryRead<'a, Endian> for MasternodeEntry {
    fn try_read(bytes: &'a [u8], _ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let provider_registration_transaction_hash =
            bytes.read_with::<UInt256>(offset, byte::LE)?;
        let confirmed_hash = bytes.read_with::<UInt256>(offset, byte::LE)?;
        let ip_address = bytes.read_with::<UInt128>(offset, byte::LE)?;
        let port = bytes.read_with::<u16>(offset, byte::LE)?.swap_bytes();
        let socket_address = SocketAddress { ip_address, port };
        let operator_public_key = bytes.read_with::<UInt384>(offset, byte::LE)?;
        let key_id_voting = bytes.read_with::<UInt160>(offset, byte::LE)?;
        let is_valid = bytes.read_with::<u8>(offset, byte::LE).unwrap_or(0);
        Ok((
            Self::new(
                provider_registration_transaction_hash,
                confirmed_hash,
                socket_address,
                key_id_voting,
                operator_public_key,
                is_valid,
            ),
            *offset,
        ))
    }
}

impl MasternodeEntry {
    pub fn new(
        provider_registration_transaction_hash: UInt256,
        confirmed_hash: UInt256,
        socket_address: SocketAddress,
        key_id_voting: UInt160,
        operator_public_key: UInt384,
        is_valid: u8,
    ) -> Self {
        let entry_hash = MasternodeEntry::calculate_entry_hash(
            provider_registration_transaction_hash,
            confirmed_hash,
            socket_address,
            operator_public_key,
            key_id_voting,
            is_valid,
        );
        Self {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: Some(
                Self::hash_confirmed_hash(confirmed_hash, provider_registration_transaction_hash),
            ),
            socket_address,
            operator_public_key,
            previous_operator_public_keys: Default::default(),
            previous_entry_hashes: Default::default(),
            previous_validity: Default::default(),
            known_confirmed_at_height: None,
            update_height: 0,
            key_id_voting,
            is_valid: is_valid != 0,
            entry_hash,
        }
    }

    fn calculate_entry_hash(
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
        *offset += provider_registration_transaction_hash
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += confirmed_hash.consensus_encode(&mut buffer).unwrap();
        *offset += socket_address
            .ip_address
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += socket_address
            .port
            .swap_bytes()
            .consensus_encode(&mut buffer)
            .unwrap();
        *offset += operator_public_key.consensus_encode(&mut buffer).unwrap();
        *offset += key_id_voting.consensus_encode(&mut buffer).unwrap();
        *offset += is_valid.consensus_encode(&mut buffer).unwrap();
        UInt256(sha256d::Hash::hash(&buffer).into_inner())
    }

    pub fn confirmed_hash_at(&self, block_height: u32) -> Option<UInt256> {
        match self.known_confirmed_at_height {
            Some(h) => {
                if h > block_height {
                    None
                } else {
                    Some(self.confirmed_hash)
                }
            }
            None => None,
        }
    }

    pub fn update_confirmed_hash(&mut self, hash: UInt256) {
        self.confirmed_hash = hash;
        if !self.provider_registration_transaction_hash.is_zero() {
            self.update_confirmed_hash_hashed_with_provider_registration_transaction_hash();
        }
    }

    pub fn update_confirmed_hash_hashed_with_provider_registration_transaction_hash(&mut self) {
        let hash = Self::hash_confirmed_hash(
            self.confirmed_hash,
            self.provider_registration_transaction_hash,
        );
        self.confirmed_hash_hashed_with_provider_registration_transaction_hash = Some(hash)
    }

    pub fn confirmed_hash_hashed_with_provider_registration_transaction_hash_at(
        &self,
        block_height: u32,
    ) -> Option<UInt256> {
        if self.known_confirmed_at_height.is_none()
            || self.known_confirmed_at_height? <= block_height
        {
            self.confirmed_hash_hashed_with_provider_registration_transaction_hash
        } else {
            Some(Self::hash_confirmed_hash(
                UInt256::default(),
                self.provider_registration_transaction_hash,
            ))
        }
    }

    pub fn host(&self) -> String {
        let ip = self.socket_address.ip_address;
        let port = self.socket_address.port;
        format!("{}:{}", ip.to_string(), port.to_string())
    }

    pub fn payload_data(&self) -> UInt256 {
        Self::calculate_entry_hash(
            self.provider_registration_transaction_hash,
            self.confirmed_hash,
            self.socket_address,
            self.operator_public_key,
            self.key_id_voting,
            if self.is_valid { 1 } else { 0 },
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
        for (Block { height, .. }, validity) in self.previous_validity.clone() {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
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
        for (Block { height, .. }, key) in self.previous_operator_public_keys.clone() {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
                min_distance = distance;
                used_previous_operator_public_key_at_block_hash = key;
            }
        }
        used_previous_operator_public_key_at_block_hash
    }

    pub fn entry_hash_at(&self, block_height: u32) -> UInt256 {
        if self.previous_entry_hashes.len() == 0 || block_height == u32::MAX {
            return self.entry_hash.clone();
        }
        let hashes: BTreeMap<Block, UInt256> = self.previous_entry_hashes.clone();
        let mut min_distance = u32::MAX;
        let mut used_hash = self.entry_hash.clone();
        for (Block { height, .. }, hash) in hashes {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
                min_distance = distance;
                println!("SME Hash for proTxHash {:?} : Using {:?} instead of {:?} for list at block height {}", self.provider_registration_transaction_hash, hash, used_hash, block_height);
                used_hash = hash;
            }
        }
        used_hash
    }

    pub fn unique_id(&self) -> String {
        short_hex_string_from(&self.provider_registration_transaction_hash.0)
    }

    pub fn update_with_previous_entry(&mut self, entry: &mut MasternodeEntry, block: Block) {
        self.previous_validity = (*entry)
            .previous_validity
            .clone()
            .into_iter()
            .filter(|(block, _)| block.height < self.update_height)
            .collect();
        if (*entry).is_valid_at(self.update_height) != self.is_valid {
            self.previous_validity
                .insert(block.clone(), (*entry).is_valid.clone());
        }
        self.previous_operator_public_keys = (*entry)
            .previous_operator_public_keys
            .clone()
            .into_iter()
            .filter(|(block, _)| block.height < self.update_height)
            .collect();
        if (*entry).operator_public_key_at(self.update_height) != self.operator_public_key {
            self.previous_operator_public_keys
                .insert(block.clone(), (*entry).operator_public_key.clone());
        }
        let old_prev_mn_entry_hashes = (*entry)
            .previous_entry_hashes
            .clone()
            .into_iter()
            .filter(|(block, _)| (*block).height < self.update_height)
            .collect();
        self.previous_entry_hashes = old_prev_mn_entry_hashes;
        if (*entry).entry_hash_at(self.update_height) != self.entry_hash {
            self.previous_entry_hashes
                .insert(block.clone(), (*entry).entry_hash.clone());
        }
    }

    pub fn update_with_block_height(&mut self, block_height: u32) {
        self.update_height = block_height;
        if !self.confirmed_hash.is_zero() && block_height != u32::MAX {
            self.known_confirmed_at_height = Some(block_height);
        }
    }
}
