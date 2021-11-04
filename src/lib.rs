mod common;
mod consensus;
mod crypto;
mod keys;
mod masternode;
mod transactions;
mod util;

pub mod manager {
    use std::{mem, ptr, slice};
    use std::array::IntoIter;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::intrinsics::size_of;
    use std::iter::FromIterator;
    use std::ptr::null;
    use blake3::Hash;
    use byte::*;
    use secrets::traits::AsContiguousBytes;


    use crate::common::llmq_type::LLMQType;
    use crate::common::merkle_tree::{MerkleTree, MerkleTreeHashFunction};
    use crate::consensus::encode::VarInt;
    use crate::crypto::byte_util::hex_with_data;
    use crate::masternode::masternode_list::MasternodeList;
    use crate::masternode::quorum_entry::QuorumEntry;
    use crate::masternode::masternode_entry::{MN_ENTRY_PAYLOAD_LENGTH, MasternodeEntry};
    use crate::transactions::coinbase_transaction::CoinbaseTransaction;
    use crate::transactions::transaction::Transaction;


    #[repr(C)]
    #[derive(Debug)]
    pub struct Result<'a> {
        pub found_coinbase: bool, //1 byte
        // pub valid_coinbase: bool, //1 byte
        // pub root_mn_list_valid: bool, //1 byte
        // pub root_quorum_list_valid: bool, //1 byte
        // pub valid_quorums: bool, //1 byte
        // pub masternode_list: Option<*mut MasternodeList<'a>>,
        // pub added_masternodes: Option<*mut HashMap<[u8; 32], MasternodeEntry>>,
        // pub modified_masternodes: Option<*mut HashMap<[u8; 32], MasternodeEntry>>,
        // pub added_quorums: Option<*mut HashMap<LLMQType, *mut HashMap<[u8; 32], QuorumEntry>>>,
        // pub needed_masternode_lists: Option<*mut HashSet<[u8; 32]>>,

        // pub value_length: usize, //8 bytes
        // pub value: *mut u8, //value_length bytes
    }

    /*#[derive(Deserialize, Debug)]
    pub struct BlockData<'a> {
        pub version: u32,
        pub hash: &'a str,
        pub previousblockhash: &'a str,
        pub merkleroot: &'a str,
        pub time: u64,
        pub bits: &'a str,
        pub chainwork: &'a str,
        pub height: u32,
    }*/

    // pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> u32;
    // pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> Option<MasternodeList>;
    // pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: [u8; 32]) -> bool;
    // pub type ShouldProceeQuorumTypeCallback = unsafe extern "C" fn(quorum_type: LLMQType) -> bool;

    pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *const u8) -> u32;
    pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *const u8) -> Option<MasternodeList>;
    pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *const u8) -> bool;
    pub type ShouldProceeQuorumTypeCallback = unsafe extern "C" fn(quorum_type: LLMQType) -> bool;



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

    fn boxed<T>(obj: T) -> *mut T {
        Box::into_raw(Box::new(obj))
    }

    fn failure() -> *mut Result {
        boxed(Result {
            found_coinbase: false,
            // valid_coinbase: false,
            // root_mn_list_valid: false,
            // root_quorum_list_valid: false,
            // valid_quorums: false,
            // masternode_list: None,
            // added_masternodes: None,
            // modified_masternodes: None,
            // added_quorums: None,
            // needed_masternode_lists: None,
        })
    }

    #[no_mangle]
    pub extern fn process_diff(
        c_array: *const u8,
        length: usize,
        base_masternode_list: Option<MasternodeList>,
        masternode_list_lookup: MasternodeListLookup,
        merkle_root: *const u8,
        use_insight_lookup: AddInsightBlockingLookup,
        should_process_quorum_of_type: ShouldProceeQuorumTypeCallback,
        block_height_lookup: BlockHeightLookup
    ) -> *mut Result {
        let message: &[u8] = unsafe { slice::from_raw_parts(c_array, length as usize) };
        let desired_merkle_root = unsafe {
            slice::from_raw_parts(merkle_root, 32) as &[u8; 32]
        };

        // NSUInteger length = message.length;
        let offset = &mut 0;
        if length - offset < 32 { return failure(); }
        // let _base_block_hash = message.read_with::<[u8; 32]>(offset, LE)?;
        let _base_block_hash = match message.read_with::<[u8; 32]>(offset, LE) {
            Ok(data) => data,
            Err(_err) => failure()
        };
        if length - offset < 32 { return failure(); }
        //let block_hash = message.read_with::<[u8; 32]>(offset, LE)?;
        let block_hash = match message.read_with::<[u8; 32]>(offset, LE) {
            Ok(data) => data,
            Err(_err) => failure()
        };
        if length - offset < 4 { return failure(); }
        let total_transactions = message.read_with::<u32>(offset, LE)?;
        if length - offset < 1 { return failure(); }
        const MERKLE_HASH_COUNT_LENGTH: usize = VarInt(message.read(offset) as u64).len();
        let merkle_hashes = message.read_with::<[u8; MERKLE_HASH_COUNT_LENGTH]>(offset, LE)?;
        const MERKLE_FLAG_COUNT_LENGTH: usize = VarInt(message.read(offset) as u64).len();
        let merkle_flags = message.read_with::<[u8; MERKLE_FLAG_COUNT_LENGTH]>(offset, LE)?;
        let coinbase_transaction = CoinbaseTransaction::new(message);
        if coinbase_transaction.is_none() { return failure(); }
        //offset += coinbase_transaction.payload_offset;
        if length - offset < 1 { return failure(); }
        let mut deleted_masternode_count: VarInt = VarInt(message.read(offset) as u64);
        while deleted_masternode_count -= 1 >= 1 {
            deleted_masternode_hashes.push(match message.read_with::<[u8; 32]>(offset, LE) {
                Ok(data) => data,
                Err(_err) => failure()
            });
        }
        //let deleted_masternode_hashes: Vec<[u8; 32]> = (0..deleted_masternode_count).into_iter().map(|i| message.read_with::<[u8; 32]>(offset, LE)?).collect();
        let mut added_masternode_count: VarInt = VarInt(message.read(offset) as u64);
        let mut added_or_modified_masternodes: HashMap<[u8; 32], MasternodeEntry> = HashMap::with_capacity(added_masternode_count as usize);


        let block_height = block_height_lookup(block_hash.as_ptr());
        while added_masternode_count >= 1 {
            if length - offset < MN_ENTRY_PAYLOAD_LENGTH { return failure(); }
            if let Some(mn_entry_payload) = message.read_with::<[u8; MN_ENTRY_PAYLOAD_LENGTH]>(offset, LE) {
                let mut mn_entry = MasternodeEntry::new(&mn_entry_payload, block_height);
                let mut key = mn_entry.provider_registration_transaction_hash.clone();
                key.reverse();
                added_or_modified_masternodes[key] = boxed(mn_entry);
            }
            added_masternode_count -= 1;
            //offset += MN_ENTRY_PAYLOAD_LENGTH;
        }



        // let block_hash = match message.read_with::<[u8; 32]>(offset, LE) {
        //     Ok(data) => data,
        //     Err(_err) => failure()
        // };



        let mut added_masternodes = added_or_modified_masternodes.clone();
        let mut modified_masternode_keys: HashSet<[u8; 32]> = HashSet::new();

        if base_masternode_list.is_some() {
            base_masternode_list?
                .masternodes
                .into_iter()
                .for_each(|(hash)| { added_masternodes.remove(h); });
            modified_masternode_keys = added_or_modified_masternodes
                .keys()
                .cloned()
                .collect()
                .intersection(base_masternode_list?
                    .masternodes
                    .keys()
                    .cloned()
                    .collect())
                .collect();
        }

        let modified_masternodes: HashMap<[u8; 32], MasternodeEntry> =
            modified_masternode_keys
                .iter()
                .fold(HashMap::new(), |mut acc, &item| {
                    acc[item] = added_or_modified_masternodes[item];
                    acc
                });

        let deleted_quorums: HashMap<LLMQType, Vec<[u8; 32]>> = HashMap::new();
        let added_quorums: HashMap<LLMQType, HashMap<[u8; 32], QuorumEntry>> = HashMap::new();

        let quorums_active = coinbase_transaction?.coinbase_transaction_version >= 2;
        let mut valid_quorums = true;
        let mut needed_masternode_lists: HashSet<[u8; 32]> = HashSet::new();

        if quorums_active {
            if length - offset < 1 { return failure(); }
            let mut deleted_quorums_count: VarInt = VarInt(message.read(offset) as u64);
            while deletedQuorumsCount >= 1 {
                if length - offset < 33 { return failure(); }
                let llmq_type = message.read_with::<LLMQType>(offset, LE)?;
                let llmq_hash = message.read_with::<[u8; 32]>(offset + 1, LE)?;
                if let Some(mutable_llmq_array) = deleted_quorums[llmq_type] {
                    mutable_llmq_array.push(llmq_hash);
                } else {
                    deleted_quorums[llmq_type] = vec![llmq_hash];
                }
                //offset += 1;
                deleted_quorums_count -= 1;
            }

            if length - offset < 1 { return failure(); }
            let mut added_quorums_count: VarInt = VarInt(message.read(offset) as u64);
            while added_quorums_count >= 1 {
                if let Some(mut potential_quorum_entry) = QuorumEntry::new(message, offset.to_owned()) {
                    let entry_quorum_hash = potential_quorum_entry.quorum_hash;
                    let llmq_type = potential_quorum_entry.llmq_type;
                    if should_process_quorum_of_type(llmq_type) {
                        if let Some(quorum_masternode_list) = masternode_list_lookup(entry_quorum_hash.as_ptr()) {
                            valid_quorums &= potential_quorum_entry.validate_with(quorum_masternode_list, block_height_lookup);
                            if !valid_quorums {
                                println!("Invalid Quorum Found For Quorum at height {:?}", quorum_masternode_list.height);
                            }
                        } else if block_height_lookup(entry_quorum_hash.as_ptr()) != u32::MAX {
                            needed_masternode_lists.insert(entry_quorum_hash);
                        } else if use_insight_lookup(entry_quorum_hash.as_ptr()) {
                            // add_insight_lookup(entry_quorum_hash);
                            // block_until_add_insight(&entry_quorum_hash, chain);
                            if block_height_lookup(entry_quorum_hash.as_ptr()) != u32::MAX {
                                needed_masternode_lists.insert(entry_quorum_hash);
                            } else {
                                println!("Quorum masternode list not found and block not available");
                            }
                        } else {
                            println!("Quorum masternode list not found and block not available");
                        }
                    }
                    if let Some(mutable_llmq_dictionary) = added_quorums[llmq_type] {
                        mutable_llmq_dictionary[entry_quorum_hash] = potential_quorum_entry;
                    } else {
                        added_quorums[llmq_type] = boxed(HashMap::<[u8; 32], QuorumEntry>::from_iter(IntoIter::new([(entry_quorum_hash, potential_quorum_entry)])));
                    }
                }
                added_quorums_count += 1;
            }
        }
        let mut masternodes =
            if let Some(list) = base_masternode_list {
                list.masternodes.clone()
            } else {
                BTreeMap::new()
            };
        for hash in deleted_masternode_hashes {
            masternodes.remove(&hash);
        }
        masternodes.extend(added_masternodes.clone());

        for (hash, mut modified) in modified_masternodes {
            let old: MasternodeEntry = masternodes[hash];
            if old.update_height < modified.update_height {
                modified.keep_info_of_previous_entry_version(old, block_height, block_hash);
            }
            masternodes[hash] = modified;
        }
        let mut quorums: HashMap<LLMQType, HashMap<[u8; 32], QuorumEntry>> =
            if base_masternode_list.is_some() {
                // we need to do a deep mutable copy
                (base_masternode_list?.quorums as HashMap<dyn Clone, dyn Clone>).clone()
            } else {
                HashMap::new()
            };
        for quorum_type in added_quorums.keys() {
            if !quorums.contains_key(quorum_type) {
                quorums[quorum_type] = HashMap::new();
            }
        }
        for quorum_type in quorums.keys() {
            let mut quorums_of_type = &quorums[quorum_type];
            if deleted_quorums.contains_key(quorum_type) {
                for deleted_quorum in deleted_quorums[quorum_type] {
                    quorums_of_type.remove(&deleted_quorum);
                }
            }
            if added_quorums.contains_key(quorum_type) {
                for (added_type, entry) in added_quorums[quorum_type] {
                    quorums_of_type.insert(added_type, entry);
                }
            }
        }
        let mut masternode_list = MasternodeList::new(masternodes, quorums, block_hash, block_height);
        let root_mn_list_valid = coinbase_transaction?.merkle_root_mn_list == masternode_list.masternode_merkle_root_with(block_height_lookup);
        // we need to check that the coinbase is in the transaction hashes we got back
        let coinbase_hash = coinbase_transaction?.base.tx_hash;
        let mut found_coinbase: bool = false;
        let mut merkle_hash_offset = &mut 0;
        for _i in 0..merkle_hashes.len() {
            if merkle_hashes.read_with::<[u8; 32]>(merkle_hash_offset, LE)? == coinbase_hash {
                found_coinbase = true;
                break;
            }
        }
        // we also need to check that the coinbase is in the merkle block
        let merkle_tree = MerkleTree {
            tree_element_count: total_transactions,
            hashes: &merkle_hashes,
            flags: &merkle_flags,
            hash_function: MerkleTreeHashFunction::SHA256_2
        };

        boxed(Result {
            found_coinbase,
            // valid_coinbase: merkle_tree.has_root(desired_merkle_root),
            // root_mn_list_valid,
            // root_quorum_list_valid: !quorums_active || coinbase_transaction?.merkle_root_llmq_list == masternode_list.quorum_merkle_root,
            // valid_quorums,
            // masternode_list: Some(boxed(masternode_list)),
            // added_masternodes: Some(boxed(added_masternodes)),
            // modified_masternodes: Some(boxed(modified_masternodes)),
            // added_quorums: Some(boxed(added_quorums)),
            // needed_masternode_lists: Some(boxed(needed_masternode_lists)),
        })
    }
}




#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use bitcoin_hashes::hex::FromHex;
    use crate::common::llmq_type::LLMQType;
    use crate::manager;

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

    fn quorum_type_for_chain_locks(chain_type: ChainType) -> LLMQType {
        match chain_type {
            MainNet => LLMQType::LLMQType_400_60,
            TestNet => LLMQType::LLMQType_50_60,
            DevNet => LLMQType::LLMQType_10_60
        }
    }

    #[test]
    fn test_mnl() {
        let chain_type = ChainType::TestNet;
        let bytes = get_file_as_byte_vec(&"ML_at_122088.dat".to_string()).as_slice();
        let c_array = bytes.as_ptr();
        let block_height = 122088;
        let result = manager::process_diff(
            c_array,
            bytes.len(),
            None,
            |block_hash| None,
            [0u8; 32].as_ptr(),
            |hash| false,
            |llmq_type| llmq_type == quorum_type_for_chain_locks(chain_type),
            |block_hash| block_height);
        println!(result);

        let masternode_list_merkle_root: Vec<u8> = Vec::from_hex("94d0af97187af3b9311c98b1cf40c9c9849df0af55dc63b097b80d4cf6c816c5").expect("Invalid Hex String");
        // let masternode_list_merkle_root_bytes: &[u8; 32] = masternode_list_merkle_root.as_slice().as_ptr().try_into
        let equal = masternode_list_merkle_root == result.masternode_list.masternode_merkle_root;
        // let block_height: u32 = chain.height_for(block_hash);
        assert!(equal, "MNList merkle root should be valid");
        assert!(result.found_coinbase, &format!("Did not find coinbase at height {}", block_height));
        // turned off on purpose as we don't have the coinbase block
        //assert!(result.valid_coinbase, "Coinbase not valid at height {}",);
        assert!(result.root_mn_list_valid, "rootMNListValid not valid at height {}", block_height);
        assert!(result.root_quorum_list_valid, "rootQuorumListValid not valid at height {}", block_height);
        assert!(result.valid_quorums, "validQuorums not valid at height {}", block_height);
    }
}
