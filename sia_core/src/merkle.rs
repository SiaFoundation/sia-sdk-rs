use crate::types::Hash256;

mod blake2b;

pub(crate) use blake2b::{as_blocks, hash_leaves_many, hash_nodes_many};

pub(crate) const LEAF_HASH_PREFIX: &[u8; 1] = &[blake2b::LEAF_PREFIX];

// A generic Merkle tree accumulator.
pub(crate) struct Accumulator {
    trees: [Hash256; 64],
    num_leaves: u64,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Accumulator {
    pub fn new() -> Self {
        Self {
            trees: [Hash256::default(); 64],
            num_leaves: 0,
        }
    }

    const fn has_tree_at_height(&self, height: usize) -> bool {
        self.num_leaves & (1 << height) != 0
    }

    pub fn add_leaf(&mut self, mut h: Hash256) {
        let mut i = 0;
        while self.has_tree_at_height(i) {
            h = sum_node(&self.trees[i], &h);
            i += 1;
        }
        self.trees[i] = h;
        self.num_leaves += 1;
    }

    pub fn insert_node(&mut self, mut h: Hash256, height: usize) {
        let mut i = height;
        while self.has_tree_at_height(i) {
            h = sum_node(&self.trees[i], &h);
            i += 1;
        }
        self.trees[i] = h;
        self.num_leaves += 1 << height;
    }

    pub fn reset(&mut self) {
        self.trees.fill(Default::default());
        self.num_leaves = 0;
    }

    pub fn root(&self) -> Hash256 {
        let mut i = self.num_leaves.trailing_zeros() as usize;
        if i == 64 {
            return Hash256::default();
        }
        let mut root = self.trees[i];
        i += 1;
        while i < 64 {
            if self.has_tree_at_height(i) {
                root = sum_node(&self.trees[i], &root);
            }
            i += 1;
        }
        root
    }
}

pub(crate) fn sum_node(left: &Hash256, right: &Hash256) -> Hash256 {
    blake2b::sum_pair(left.as_ref(), right.as_ref()).into()
}
