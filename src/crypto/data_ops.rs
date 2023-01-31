use std::collections::HashSet;
use byte::BytesExt;

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
}

impl Data for [u8] {

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, byte::LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, byte::LE).unwrap();
            for _j in 0..8 {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
    }
}

impl Data for Vec<u8> {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        (self[(index / 8) as usize] >> (index % 8)) & 1 != 0
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        self.iter().for_each(|bits| {
            let mut bits = bits.clone();
            (0..8).for_each(|_| {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            });
        });
        count
    }
}


/// Extracts the common values in `a` and `b` into a new set.
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &mut HashSet<T>) -> HashSet<T>
    where
        T: std::hash::Hash,
        T: Eq,
{
    let x: HashSet<(T, bool)> = a
        .drain()
        .map(|v| {
            let intersects = b.contains(&v);
            (v, intersects)
        })
        .collect();
    let mut c = HashSet::new();
    for (v, is_inter) in x {
        if is_inter {
            c.insert(v);
        } else {
            a.insert(v);
        }
    }
    b.retain(|v| !c.contains(v));
    c
}
