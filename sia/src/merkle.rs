use crate::types::Hash256;
use blake2b_simd::Params;

pub const LEAF_HASH_PREFIX: &[u8; 1] = &[0];
pub const NODE_HASH_PREFIX: &[u8; 1] = &[1];

// A generic Merkle tree accumulator.
pub struct Accumulator {
    trees: [Hash256; 64],
    num_leaves: u64,
    params: Params,
}

impl Accumulator {
    pub fn new() -> Self {
        let mut params = Params::new();
        params.hash_length(32);
        Self {
            trees: [Hash256::default(); 64],
            num_leaves: 0,
            params,
        }
    }

    const fn has_tree_at_height(&self, height: usize) -> bool {
        self.num_leaves & (1 << height) != 0
    }

    pub fn add_leaf(&mut self, h: &Hash256) {
        let mut i = 0;
        let mut node = *h;
        while self.has_tree_at_height(i) {
            node = sum_node(&self.params, &self.trees[i], h);
            i += 1;
        }
        self.trees[i] = node;
        self.num_leaves += 1;
    }

    pub fn insert_node(&mut self, h: &Hash256, height: usize) {
        let mut h = *h;
        let mut i = height;
        while self.has_tree_at_height(i) {
            h = sum_node(&self.params, &self.trees[i], &h);
            i += 1;
        }
        self.trees[height] = h;
        self.num_leaves += 1 << height;
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
                root = sum_node(&self.params, &self.trees[i], &root);
            }
            i += 1;
        }
        root
    }
}

#[allow(dead_code)]
pub fn sum_leaf(params: &Params, leaf: &[u8]) -> Hash256 {
    let h = params
        .to_state()
        .update(LEAF_HASH_PREFIX)
        .update(leaf)
        .finalize();

    h.into()
}

pub fn sum_node(params: &Params, left: &Hash256, right: &Hash256) -> Hash256 {
    let h = params
        .to_state()
        .update(NODE_HASH_PREFIX)
        .update(left.as_ref())
        .update(right.as_ref())
        .finalize();

    h.into()
}
