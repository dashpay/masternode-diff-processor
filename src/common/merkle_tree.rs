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

impl MerkleTree<'static> {
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
        let mut data = [0u8].as_bytes();
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag | hash,
            |left, right| {
                let offset: &mut usize = &mut 0;
                data.write(offset, left);
                // if right branch is missing, duplicate left branch
                data.write(offset, if right.is_none() { left.clone() } else { right? });
                Some(UInt256(sha256d::Hash::hash(data).into_inner()))
            })
    }

    fn foo<F: Fn(i32) -> i32>(a: i32, f: F) -> i32 {
        f(a)
    }

    pub fn walk_hash_idx<BL: Fn(UInt256, Option<UInt256>) -> Option<UInt256>>(
        &self,
        mut hash_idx: &mut i32,
        mut flag_idx: &mut i32,
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
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch)?;
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left, right)
    }

    /*fn branch_lookup(&self, data: &mut [u8], left: sha256d::Hash, mut right: Option<sha256d::Hash>) -> sha256d::Hash {
        let offset: &mut usize = &mut 0;
        data.write(offset, left.as_bytes());
        // if right branch is missing, duplicate left branch
        data.write(offset, if right.is_none() { left.as_bytes().clone() } else { right?.as_bytes() });
        sha256d::Hash::hash(data)
    }*/

    /*pub fn has_root<T: hashes::Hash>(&self, desired_merkle_root: T) -> bool {
        self.tree_element_count == 0 || self.merkle_root() == desired_merkle_root
    }

    pub fn merkle_root<T: hashes::Hash>(&self) -> Option<T> {
        let hash_idx = &mut 0;
        let flag_idx = &mut 0;
        let mut data = [0u8].as_bytes();
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag | hash,
            |left, right| {
                let offset: &mut usize = &mut 0;
                data.write(offset, left);
                // if right branch is missing, duplicate left branch
                data.write(offset, if right.is_none() { left.clone() } else { right });
                Some(self.hash_function(data))
            })
    }

    pub fn walk_hash_idx<T: hashes::Hash>(
        &self,
        mut hash_idx: &mut i32,
        mut flag_idx: &mut i32,
        depth: i32,
        leaf: LeafLookup<T>,
        branch: BranchLookup<T>
    ) -> Option<sha256d::Hash> {
        let flags_length = self.flags.len() as i32;
        let hashes_length = self.hashes.len() as i32;
        if *flag_idx / 8 >= flags_length || (*hash_idx + 1) * 32 > hashes_length {
            return leaf(None, false);
        }
        let flag = self.flags[*flag_idx / 8] & (1 << (*flag_idx % 8));
        flag_idx += 1;
        if !flag || depth == ceil_log2(self.tree_element_count as i32) {
            //buffer.write(offset, self.version);
            let offset: &mut usize = hash_idx*32;
            return if let Some(hash) = self.hashes.read_with::<sha256d::Hash>(offset) {
                leaf(Some(hash), flag)
            } else {
                None
            };
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch)?;
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left, right)
    }

    fn hash(&self, data: &[u8]) -> dyn hashes::Hash {
        match self.hash_function {
            MerkleTreeHashFunction::SHA256_2 => sha256d::Hash::hash(data),
            MerkleTreeHashFunction::BLAKE3 => blake3_wrapper::Hash::hash(data)
        }
    }

    fn branch_lookup<T: hashes::Hash>(&self, data: &mut [u8], left: T, mut right: Option<T>) -> T {
        let offset: &mut usize = &mut 0;
        data.write(offset, left);
        // if right branch is missing, duplicate left branch
        data.write(offset, if right.is_none() { left.clone() } else { right });
        self.hash_function(data)
    }*/

}
