use std::sync::{Arc, Mutex};
use hashes::{sha256d};
use byte::{BytesExt, LE};
use secrets::traits::AsContiguousBytes;
use crate::crypto::byte_util::UInt256;
use crate::hashes::Hash;

// pub enum MerkleTreeHashFunction {
//     SHA256_2 = 0,
//     BLAKE3 = 1,
// }

// pub type HashFunction<T: hashes::Hash> = fn(data: &[u8]) -> T;
// pub type LeafLookup<T: hashes::Hash> = fn(hash: Option<T>, flag: bool) -> Option<T>;
// pub type BranchLookup<T: hashes::Hash> = fn(left: T, right: Option<T>) -> Option<T>;

pub type LeafLookup = fn(hash: Option<UInt256>, flag: bool) -> Option<UInt256>;
pub type BranchLookup = fn(left: UInt256, right: Option<UInt256>) -> Option<UInt256>;

#[inline]
fn ceil_log2(mut x: i32) -> i32 {
    let mut r = if x & (x - 1) != 0 { 1 } else { 0 };
    loop {
        x >>= 1;
        if x == 0 {
            break;
        }
        r += 1;
    }
    r
}

#[derive(Clone, Debug)]
pub struct MerkleTree<'a> {
    pub tree_element_count: u32,
    pub hashes: &'a [u8],
    pub flags: &'a [u8],
    // pub hash_function: HashFunction<T>,
    // pub hash_function: MerkleTreeHashFunction,
}

impl<'a> MerkleTree<'a> {
    pub fn has_root(&self, desired_merkle_root: UInt256) -> bool {
        //self.tree_element_count == 0 || self.merkle_root() == desired_merkle_root
        if self.tree_element_count == 0 {
            return true;
        }
        if let Some(root) = self.merkle_root() {
            if root == desired_merkle_root {
                return true;
            }
        }
        return false;
    }

    pub fn merkle_root(&self) -> Option<UInt256> {
        let hash_idx = &mut 0;
        let flag_idx = &mut 0;
        //let mut buffer = [0u8];
        let buffer: &mut [u8] = &mut [];

        // let mut buffer = Arc::new(Mutex::new([0u8]));

        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag | hash,
            |left, right| {
                let offset: &mut usize = &mut 0;
                buffer.write(offset, left);
                // buffer.lock().unwrap().write(offset, left);
                // if right branch is missing, duplicate left branch
                buffer.write(offset, if right.is_none() { left.clone() } else { right.unwrap() });
                // buffer.lock().unwrap().write(offset, if right.is_none() { left.clone() } else { right.unwrap() });
                Some(UInt256(sha256d::Hash::hash(buffer.as_bytes()).into_inner()))
                // Some(UInt256(sha256d::Hash::hash(buffer.lock().unwrap().as_bytes()).into_inner()))
            })
    }

    pub fn walk_hash_idx<BL: FnMut(UInt256, Option<UInt256>) -> Option<UInt256>>(
        &self,
        hash_idx: &mut i32,
        flag_idx: &mut i32,
        depth: i32,
        leaf: LeafLookup,
        branch: BL
    ) -> Option<UInt256> {
        let flags_length = self.flags.len() as i32;
        let hashes_length = self.hashes.len() as i32;
        if *flag_idx / 8 >= flags_length || (*hash_idx + 1) * 32 > hashes_length {
            return leaf(None, false);
        }
        let flag = self.flags[(*flag_idx / 8) as usize] & (1 << (*flag_idx % 8)) != 0;
        *flag_idx += 1;
        if !flag || depth == ceil_log2(self.tree_element_count as i32) {
            let off = &mut ((*hash_idx*32) as usize);
            return if let Ok(hash) = self.hashes.read_with::<UInt256>(off, LE) {
                leaf(Some(hash), flag)
            } else {
                None
            };
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left.unwrap(), right)
    }

    /*
    fn hash(&self, data: &[u8]) -> dyn hashes::Hash {
        match self.hash_function {
            MerkleTreeHashFunction::SHA256_2 => sha256d::Hash::hash(data),
            MerkleTreeHashFunction::BLAKE3 => blake3_wrapper::Hash::hash(data)
        }
    }
    */

}
