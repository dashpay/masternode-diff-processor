use dash_spv_primitives::consensus::Encodable;
use dash_spv_primitives::crypto::byte_util::{BytesDecodable, UInt256};
use dash_spv_primitives::hashes::{Hash, sha256d};

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
}

impl<'a> MerkleTree<'a> {
    pub fn has_root(&self, desired_merkle_root: UInt256) -> bool {
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
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag | hash,
            |left, right| {
                let mut buffer: Vec<u8> = Vec::with_capacity(64);
                left.consensus_encode(&mut buffer).unwrap();
                right.unwrap_or(left.clone()).consensus_encode(&mut buffer).unwrap();
                let hash = sha256d::Hash::hash(&buffer);
                let value = hash.into_inner();
                Some(UInt256(value))
            })
    }

    pub fn walk_hash_idx<
        BL: Fn(UInt256, Option<UInt256>) -> Option<UInt256> + Copy,
        LL: Fn(Option<UInt256>, bool) -> Option<UInt256> + Copy>(
        &self, hash_idx: &mut i32, flag_idx: &mut i32,
        depth: i32, leaf: LL, branch: BL) -> Option<UInt256> {
        let flags_length = self.flags.len() as i32;
        let hashes_length = self.hashes.len() as i32;
        if *flag_idx / 8 >= flags_length || (*hash_idx + 1) * 32 > hashes_length {
            return leaf(None, false);
        }
        let flag = self.flags[(*flag_idx / 8) as usize] & (1 << (*flag_idx % 8)) != 0;
        *flag_idx += 1;
        if !flag || depth == ceil_log2(self.tree_element_count as i32) {
            let off = &mut (32*(*hash_idx) as usize);
            let hash = UInt256::from_bytes(self.hashes, off)?;
            *hash_idx += 1;
            return leaf(Some(hash), flag);
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left.unwrap(), right)
    }
}
