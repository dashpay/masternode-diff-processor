pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;

#[cfg(feature = "std")]
use std::io;
#[cfg(not(feature = "std"))]
use core2::io;

#[macro_use]
mod internal_macros;
mod common;
mod consensus;
mod crypto;
mod keys;
mod masternode;
mod transactions;
mod util;
mod blockdata;
mod network;
mod hash_types;

pub mod manager {
    use std::{mem, slice};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use byte::*;
    use hashes::hex::ToHex;

    use crate::common::llmq_type::LLMQType;
    use crate::common::merkle_tree::{MerkleTree};
    use crate::consensus::Decodable;
    use crate::consensus::encode::VarInt;
    use crate::crypto::byte_util::{Data, merkle_root_from_hashes, MNPayload, Reversable, UInt256, UInt384};
    use crate::crypto::data_ops::inplace_intersection;
    use crate::masternode::masternode_list::MasternodeList;
    use crate::masternode::quorum_entry::QuorumEntry;
    use crate::masternode::masternode_entry::{MasternodeEntry};
    use crate::transactions::coinbase_transaction::CoinbaseTransaction;


    #[repr(C)]
    #[derive(Debug)]
    pub struct Result<'a> {
        pub found_coinbase: bool, //1 byte
        pub valid_coinbase: bool, //1 byte
        pub root_mn_list_valid: bool, //1 byte
        pub root_quorum_list_valid: bool, //1 byte
        pub valid_quorums: bool, //1 byte
        pub masternode_list: BaseMasternodeList,
        pub added_masternodes: Option<*mut BTreeMap<UInt256, MasternodeEntry>>,
        pub modified_masternodes: Option<*mut BTreeMap<UInt256, MasternodeEntry>>,
        pub added_quorums: Option<*mut HashMap<LLMQType, HashMap<UInt256, QuorumEntry<'a>>>>,
        pub needed_masternode_lists: Option<*mut HashSet<UInt256>>,

        // pub value_length: usize, //8 bytes
        // pub value: *mut u8, //value_length bytes
    }

    // pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> u32;
    // pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> Option<MasternodeList>;
    // pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> bool;

    pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *const u8) -> u32;
    pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *const u8) -> BaseMasternodeList;
    pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *const u8) -> bool;
    pub type ShouldProceeQuorumTypeCallback = unsafe extern "C" fn(quorum_type: LLMQType) -> bool;
    pub type ValidateOperatorCallback = unsafe extern "C" fn(public_key_signatures: Vec<UInt384>) -> bool;
    pub type ValidateOperatorPublicKeySignaturesFunc = unsafe extern "C" fn(
        items: *mut *mut UInt384, // 8 bytes
        count: usize // sizeof(pointer)
    ) -> bool;


    //pub struct BaseMasternodeList(pub Option<MasternodeList>);

    #[repr(C)]
    #[derive(Debug)]
    pub struct BaseMasternodeList(pub Option<*mut MasternodeList<'static>>);

    /*pub fn block_until_add_insight(block_hash: &[u8; 32], chain: Chain) {
        assert_ne!(block_hash, 0);
        let insight_url = if chain.is_main_net() {INSIGHT_URL} else {TESTNET_INSIGHT_URL};
        let path = format!("{}{}{}", insight_url, BLOCK_PATH, hex_with_data(block_hash)).as_str();
        let client = Client::new();
        let uri = path.parse()?;
        let mut resp = client.get(uri).await?;
        println!("Response: {}", resp.status());
        let mut body = Vec::new();
        while let Some(chunk) = resp.body_mut().next().await {
            body.extend_from_slice(&chunk?);
        }
        let block_data: BlockData = serde_json::from_slice(&body)?;
        chain.add_insight_verified_block(block_data);
    }*/

    fn boxed<T>(obj: T) -> *mut T { Box::into_raw(Box::new(obj)) }

    fn failure<'a>() -> *mut Result<'a> {
        boxed(Result {
            found_coinbase: false,
            valid_coinbase: false,
            root_mn_list_valid: false,
            root_quorum_list_valid: false,
            valid_quorums: false,
            masternode_list: BaseMasternodeList(None),
            added_masternodes: None,
            modified_masternodes: None,
            added_quorums: None,
            needed_masternode_lists: None,
        })
    }

    #[no_mangle]
    pub extern fn process_diff(
        c_array: *const u8,
        length: usize,
        base_masternode_list: BaseMasternodeList,
        masternode_list_lookup: MasternodeListLookup,
        merkle_root: *const u8,
        use_insight_lookup: AddInsightBlockingLookup,
        should_process_quorum_of_type: ShouldProceeQuorumTypeCallback,
        validate_operator_signatures: ValidateOperatorPublicKeySignaturesFunc,
        block_height_lookup: BlockHeightLookup
    ) -> *mut Result<'static> {
        let message: &[u8] = unsafe { slice::from_raw_parts(c_array, length as usize) };
        let merkle_root_bytes = unsafe { slice::from_raw_parts(merkle_root, 32) };
        let desired_merkle_root = match merkle_root_bytes.read_with::<UInt256>(&mut 0, LE) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let offset = &mut 0;
        let _base_block_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let _base_block_hash_hex = _base_block_hash.0.to_hex();

        let block_hash = match message.read_with::<UInt256>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let _block_hash_hex = block_hash.0.to_hex();
        let block_height = unsafe { block_height_lookup(block_hash.0.as_ptr()) };
        let total_transactions = match message.read_with::<u32>(offset, LE) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let merkle_hash_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let merkle_hash_count_length = merkle_hash_var_int.len();
        *offset += merkle_hash_count_length;
        let merkle_hashes_count = (merkle_hash_var_int.0 as usize) * 32;
        let merkle_hashes = &message[*offset..*offset + merkle_hashes_count];
        *offset += merkle_hashes_count;
        let merkle_flag_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        let merkle_flag_count_length = merkle_flag_var_int.len();
        *offset += merkle_flag_count_length;

        let merkle_flag_count = merkle_flag_var_int.0 as usize;
        let merkle_flags = &message[*offset..*offset + merkle_flag_count];
        *offset += merkle_flag_count;

        let coinbase_transaction = CoinbaseTransaction::new(&message[*offset..]);

        if coinbase_transaction.is_none() { return failure(); }
        let coinbase_transaction = coinbase_transaction.unwrap();

        let _block_hash_hex = block_hash.0.to_hex();
        let _coinbase_tx_hash = coinbase_transaction.base.tx_hash.unwrap().0.to_hex();

        *offset += coinbase_transaction.base.payload_offset;
        if length - *offset < 1 { return failure(); }
        let deleted_masternode_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        *offset += deleted_masternode_var_int.len();
        let deleted_masternode_count = deleted_masternode_var_int.0.clone();
        let mut deleted_masternode_hashes: Vec<UInt256> = Vec::new();
        for _i in 0..deleted_masternode_count {
            deleted_masternode_hashes.push(match message.read_with::<UInt256>(offset, LE) {
                Ok(data) => data,
                Err(_err) => { return failure(); }
            });
        }
        let added_masternode_var_int = match VarInt::consensus_decode(&message[*offset..]) {
            Ok(data) => data,
            Err(_err) => { return failure(); }
        };
        *offset += added_masternode_var_int.len();
        let added_masternode_count = added_masternode_var_int.0.clone();
        let added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = (0..added_masternode_count)
            .into_iter()
            .map(|_i| message.read_with::<MNPayload>(offset, LE))
            .filter(|payload| payload.is_ok())
            .map(|payload| MasternodeEntry::new(payload.unwrap(), block_height))
            .filter(|entry| entry.is_some())
            .fold(BTreeMap::new(),|mut acc, entry| {
                let mut mn_entry = entry.unwrap();
                acc.insert(mn_entry.provider_registration_transaction_hash.reversed(), mn_entry);
                acc
            });
        let mut added_masternodes = added_or_modified_masternodes.clone();
        let mut modified_masternode_keys: HashSet<UInt256> = HashSet::new();
        let (has_old, old_masternodes, old_quorums) = if base_masternode_list.0.is_some() {
            let list = unsafe { Box::from_raw(base_masternode_list.0.unwrap()) };
            (true, list.masternodes, list.quorums)
        } else {
            (false, BTreeMap::new(), HashMap::new())
        };
        if has_old {
            let base_masternodes = old_masternodes.clone();
            base_masternodes
                .iter()
                .for_each(|(h, _e)| { added_masternodes.remove(h); });

           let mut new_mn_keys: HashSet<UInt256> = added_or_modified_masternodes
               .clone()
               .keys()
               .cloned()
               .collect();
            let mut old_mn_keys: HashSet<UInt256> = base_masternodes
                .keys()
                .cloned()
                .collect();
            modified_masternode_keys = inplace_intersection(&mut new_mn_keys, &mut old_mn_keys);
        }

        let modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = modified_masternode_keys
            .clone()
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, hash| {
                acc.insert(hash, added_or_modified_masternodes[&hash].clone());
                acc
        });

        let mut deleted_quorums: HashMap<LLMQType, Vec<UInt256>> = HashMap::new();
        let mut added_quorums: HashMap<LLMQType, HashMap<UInt256, QuorumEntry>> = HashMap::new();

        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        let mut valid_quorums = true;
        let mut needed_masternode_lists: HashSet<UInt256> = HashSet::new();

        if quorums_active {
            // deleted quorums
            if length - *offset < 1 { return failure(); }
            let deleted_quorums_var_int = match VarInt::consensus_decode(&message[*offset..]) {
                Ok(data) => data,
                Err(_err) => { return failure(); }
            };
            *offset += deleted_quorums_var_int.len();
            let deleted_quorums_count = deleted_quorums_var_int.0.clone();
            for _i in 0..deleted_quorums_count {
                let llmq_type = match message.read_with::<LLMQType>(offset, LE) {
                    Ok(data) => data,
                    Err(_err) => { return failure(); }
                };
                let llmq_hash = match message.read_with::<UInt256>(offset, LE) {
                    Ok(data) => data,
                    Err(_err) => { return failure(); }
                };
                if deleted_quorums.contains_key(&llmq_type) {
                    deleted_quorums.get_mut(&llmq_type).unwrap().push(llmq_hash);
                } else {
                    deleted_quorums.insert(llmq_type, vec![llmq_hash]);
                }
            }

            // added quorums
            if length - *offset < 1 { return failure(); }
            let added_quorums_var_int = match VarInt::consensus_decode(&message[*offset..]) {
                Ok(data) => data,
                Err(_err) => { return failure(); }
            };
            *offset += added_quorums_var_int.len();
            let added_quorums_count = added_quorums_var_int.0.clone();
            for _i in 0..added_quorums_count {
                if let Some(mut quorum_entry) = QuorumEntry::new(message, *offset) {
                    let entry_quorum_hash = quorum_entry.quorum_hash;
                    let llmq_type = quorum_entry.llmq_type;
                    if unsafe { should_process_quorum_of_type(llmq_type) } {
                        let bmn_list = unsafe { masternode_list_lookup(entry_quorum_hash.0.as_ptr()) };
                        if let Some(quorum_mn_list) = bmn_list.0 {
                            let is_valid_payload = quorum_entry.validate_payload();
                            let quorum_masternode_list = unsafe { Box::from_raw(quorum_mn_list) };
                            let block_height: u32 = unsafe { block_height_lookup(quorum_masternode_list.block_hash.0.as_ptr()) };
                            let quorum_count = quorum_entry.llmq_type.quorum_size();
                            let quorum_modifier = quorum_entry.llmq_quorum_hash();
                            let valid_masternodes = quorum_masternode_list.valid_masternodes_for(quorum_modifier, quorum_count, block_height);
                            let mut operator_pks: Vec<*mut UInt384> = Vec::new();
                            let mut i: u32 = 0;
                            for masternode_entry in valid_masternodes {
                                if quorum_entry.signers_bitset.bit_is_true_at_le_index(i) {
                                    operator_pks.push(boxed(masternode_entry.operator_public_key_at(block_height)));
                                }
                                i += 1;
                            }
                            let mut pks_slice = operator_pks.into_boxed_slice();
                            let items = pks_slice.as_mut_ptr();
                            let items_count = pks_slice.len();
                            mem::forget(pks_slice);
                            let is_valid_signature = unsafe { validate_operator_signatures(items, items_count) };
                            valid_quorums &= is_valid_payload && is_valid_signature;
                            if valid_quorums {
                                quorum_entry.verified = true;
                            }
                        } else if unsafe { block_height_lookup(entry_quorum_hash.0.as_ptr()) } != u32::MAX {
                            needed_masternode_lists.insert(entry_quorum_hash);
                        } else if unsafe { use_insight_lookup(entry_quorum_hash.0.as_ptr()) } {
                            // add_insight_lookup(entry_quorum_hash);
                            // block_until_add_insight(&entry_quorum_hash, chain);
                            if unsafe { block_height_lookup(entry_quorum_hash.0.as_ptr()) } != u32::MAX {
                                needed_masternode_lists.insert(entry_quorum_hash);
                            } else {
                                println!("Quorum masternode list not found and block not available");
                            }
                        } else {
                            println!("Quorum masternode list not found and block not available");
                        }
                    }

                    added_quorums
                        .entry(llmq_type)
                        .or_insert(HashMap::new())
                        .insert(entry_quorum_hash, quorum_entry);
                }
            }
        }

        let mut masternodes = if has_old {
            added_masternodes.clone()
        } else {
            let mut old_mnodes = old_masternodes.clone();
            for hash in deleted_masternode_hashes {
                old_mnodes.remove(&hash);
            }
            old_mnodes.extend(added_masternodes.clone());
            old_mnodes
        };
        for (hash, mut modified) in modified_masternodes.clone() {
            if let Some(old) = masternodes.get_mut(&hash) {
                if old.update_height < modified.update_height {
                    modified.keep_info_of_previous_entry_version(old.to_owned(), block_height, block_hash);
                }
                masternodes.insert(hash, modified);
            }
        }
        let mut quorums = old_quorums.clone();

        let quorums_to_add = added_quorums
            .clone()
            .into_iter()
            .filter(|(key, _entries)| !quorums.contains_key(key))
            .collect::<HashMap<LLMQType, HashMap<UInt256, QuorumEntry>>>();

        quorums.extend(quorums_to_add);

        quorums.clone().into_iter().for_each(|(quorum_type, mut quorums_of_type)| {
            if deleted_quorums.contains_key(&quorum_type) {
                if let Some(keys_to_delete) = deleted_quorums.get(&quorum_type) {
                    keys_to_delete.iter().for_each(|key| {
                        quorums_of_type.remove(key);
                    });
                }
            }
            if added_quorums.contains_key(&quorum_type) {
                if let Some(quorums_to_add) = added_quorums.get(&quorum_type) {
                    quorums_to_add.into_iter().for_each(|(key, entry)| {
                        quorums_of_type.insert(*key, entry.to_owned());
                    });
                }
            }
        });

        let mut masternode_list = MasternodeList::new(masternodes, quorums, block_hash, block_height);
        if masternode_list.masternode_merkle_root.is_none() {
            if let Some(hashes) = masternode_list.hashes_for_merkle_root(block_height) {
                masternode_list.masternode_merkle_root = merkle_root_from_hashes(hashes);
            }
        }
        let root_mn_list_valid =
            if let Some(mn_merkle_root) = masternode_list.masternode_merkle_root {
                coinbase_transaction.merkle_root_mn_list == mn_merkle_root
            } else {
                false
            };
        // we need to check that the coinbase is in the transaction hashes we got back
        let coinbase_hash = coinbase_transaction.base.tx_hash.unwrap();
        let mut found_coinbase: bool = false;
        let merkle_hash_offset = &mut 0;
        for _i in 0..merkle_hashes.len() {
            if let Ok(h) = merkle_hashes.read_with::<UInt256>(merkle_hash_offset, LE) {
                if h == coinbase_hash {
                    found_coinbase = true;
                    break;
                }
            }
        }
        // we also need to check that the coinbase is in the merkle block
        let merkle_tree = MerkleTree {
            tree_element_count: total_transactions,
            hashes: &merkle_hashes,
            flags: &merkle_flags,
            // hash_function: |data|sha256d::Hash::hash(data)
        };

        let mut root_quorum_list_valid = true;
        if quorums_active {
            let q_merkle_root = masternode_list.q_merkle_root();
            let ct_q_merkle_root = coinbase_transaction.merkle_root_mn_list;
            root_quorum_list_valid = q_merkle_root.is_some() && ct_q_merkle_root == q_merkle_root.unwrap();
            if !root_quorum_list_valid {
                println!("Quorum Merkle root not valid for DML on block {} version {} ({:?} wanted - {:?} calculated)",
                         coinbase_transaction.height,
                         coinbase_transaction.base.version,
                         coinbase_transaction.merkle_root_llmq_list,
                         masternode_list.quorum_merkle_root);
            }
        }
        let masternode_list = BaseMasternodeList(Some(boxed(masternode_list)));
        let _desired_merkle_root_hex = desired_merkle_root.0.to_hex();
        let valid_coinbase = merkle_tree.has_root(desired_merkle_root);
        boxed(Result {
            found_coinbase,
            valid_coinbase,
            root_mn_list_valid,
            root_quorum_list_valid,
            valid_quorums,
            masternode_list,
            added_masternodes: Some(boxed(added_masternodes)),
            modified_masternodes: Some(boxed(modified_masternodes)),
            added_quorums: Some(boxed(added_quorums)),
            needed_masternode_lists: Some(boxed(needed_masternode_lists)),
        })
    }
}




#[cfg(test)]
mod tests {
    use std::{env, fs};
    use std::io::Read;
    use byte::{BytesExt, LE};
    use hashes::hex::{FromHex, ToHex};
    use crate::common::chain_type::ChainType;
    use crate::common::llmq_type::LLMQType;
    use crate::crypto::byte_util::{UInt256, UInt384};
    use crate::manager;
    use crate::manager::BaseMasternodeList;

    const CHAIN_TYPE: ChainType = ChainType::TestNet;
    const BLOCK_HEIGHT: u32 = 122088;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
        let mut f = fs::File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut buffer).expect("buffer overflow");
        buffer
    }

    unsafe extern "C" fn block_height_lookup(_block_hash: *const u8) -> u32 {
        BLOCK_HEIGHT
    }
    unsafe extern "C" fn masternode_list_lookup(_block_hash: *const u8) -> BaseMasternodeList {
        BaseMasternodeList(None)
    }
    unsafe extern "C" fn use_insight_lookup(_hash: *const u8) -> bool {
        false
    }
    unsafe extern "C" fn should_process_quorum_of_type(llmq_type: LLMQType) -> bool {
        llmq_type == match CHAIN_TYPE {
            ChainType::MainNet => LLMQType::Llmqtype40060,
            ChainType::TestNet => LLMQType::Llmqtype5060,
            ChainType::DevNet => LLMQType::Llmqtype1060
        }
    }
    unsafe extern "C" fn validate_operator_signatures(_items: *mut *mut UInt384, _count: usize) -> bool {
        true
    }

    #[test]
    fn test_mnl() {
        let executable = env::current_exe().unwrap();
        let path = match executable.parent() {
            Some(name) => name,
            _ => panic!()
        };
        let filepath = format!("{}/../../../src/{}", path.display(), "ML_at_122088.dat");
        println!("{:?}", filepath);
        let file = get_file_as_byte_vec(&filepath);
        // let file = get_file_as_byte_vec(&"../src/ML_at_122088.dat".to_string());
        let bytes = file.as_slice();
        let length = bytes.len();
        let c_array = bytes.as_ptr();
        let base_masternode_list = BaseMasternodeList(None);
        let merkle_root = [0u8; 32].as_ptr();
        let result = manager::process_diff(
            c_array,
            length,
            base_masternode_list,
            masternode_list_lookup,
            merkle_root,
            use_insight_lookup,
            should_process_quorum_of_type,
            validate_operator_signatures,
            block_height_lookup
        );
        println!("{:?}", result);

        let result = unsafe { Box::from_raw(result) };
        let masternode_list = unsafe { Box::from_raw(result.masternode_list.0.unwrap()) };
        let masternode_list_merkle_root = Vec::from_hex("94d0af97187af3b9311c98b1cf40c9c9849df0af55dc63b097b80d4cf6c816c5").expect("Invalid Hex String").read_with::<UInt256>(&mut 0, LE).unwrap();
        let obtained_mn_merkle_root = masternode_list.masternode_merkle_root.unwrap();
        let equal = masternode_list_merkle_root == obtained_mn_merkle_root;
        // let block_height: u32 = chain.height_for(block_hash);
        let pre_hex = masternode_list_merkle_root.0.to_hex();
        let obt_hex = obtained_mn_merkle_root.0.to_hex();

        assert!(equal, "MNList merkle root should be valid");
        assert!(result.found_coinbase, "Did not find coinbase at height {}", BLOCK_HEIGHT);
        // turned off on purpose as we don't have the coinbase block
        assert!(result.valid_coinbase, "Coinbase not valid at height {}", BLOCK_HEIGHT);
        assert!(result.root_mn_list_valid, "rootMNListValid not valid at height {}", BLOCK_HEIGHT);
        assert!(result.root_quorum_list_valid, "rootQuorumListValid not valid at height {}", BLOCK_HEIGHT);
        assert!(result.valid_quorums, "validQuorums not valid at height {}", BLOCK_HEIGHT);
    }
}
