use byte::BytesExt;
use secrets::traits::AsContiguousBytes;
use crate::crypto::data_ops::sha256_2;

pub enum MerkleTreeHashFunction {
    SHA256_2 = 0,
    BLAKE3 = 1,
}

pub type LeafLookup = fn(hash: Option<&[u8; 32]>, flag: bool) -> Option<&[u8; 32]>;
pub type BranchLookup = fn(left: &[u8; 32], right: Option<&[u8; 32]>) -> Option<&[u8; 32]>;


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleTree<'a> {
    pub tree_element_count: u32,
    pub hashes: &'a [u8],
    pub flags: &'a [u8],
    pub hash_function: MerkleTreeHashFunction,
}

#[inline]
fn ceil_log2(mut x: i32) -> i32 {
    let mut r = if x & (x - 1) { 1 } else { 0 };
    while x >>= 1 != 0 {
        r += 1;
    }
    r
}

impl MerkleTree {
    pub fn has_root(&self, desired_merkle_root: &[u8; 32]) -> bool {
        self.tree_element_count == 0 || self.merkle_root() == desired_merkle_root
    }

    fn branch_lookup(&self, data: &mut [u8], left: [u8; 32], mut right: Option<[u8; 32]>) -> [u8; 32] {
        let offset: &mut usize = &mut 0;
        data.write(offset, left);
        // if right branch is missing, duplicate left branch
        data.write(offset, if right.is_none() { left.clone() } else { right });
        match self.hash_function {
            MerkleTreeHashFunction::SHA256_2 => { sha256_2(data) }
            MerkleTreeHashFunction::BLAKE3 => { blake3::hash(data).as_bytes() }
        }
    }
    pub fn merkle_root(&self) -> Option<&[u8; 32]> {
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
                Some(match self.hash_function {
                    MerkleTreeHashFunction::SHA256_2 => { &sha256_2(data) }
                    MerkleTreeHashFunction::BLAKE3 => { blake3::hash(data).as_bytes() }
                })
            })
    }

    pub fn walk_hash_idx(
        &self,
        mut hash_idx: &mut i32,
        mut flag_idx: &mut i32,
        depth: i32,
        leaf: LeafLookup,
        branch: BranchLookup
    ) -> Option<&[u8; 32]> {
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
            return if let Some(hash) = self.hashes.read_with::<&[u8; 32]>(offset) {
                leaf(Some(hash), flag)
            } else {
                None
            };
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch)?;
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left, right)
    }


}
