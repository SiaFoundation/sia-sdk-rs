use crate::merkle::{sum_node, LEAF_HASH_PREFIX, NODE_HASH_PREFIX};
use crate::Hash256;
use blake2b_simd::many::{hash_many, HashManyJob};
use blake2b_simd::Params;
use rayon::prelude::*;

pub const SEGMENT_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 1 << 22;

/// Calculates the Merkle root of a sector
pub fn sector_root(sector: &[u8]) -> Hash256 {
    assert_eq!(sector.len(), SECTOR_SIZE);
    let mut params = Params::new();
    params.hash_length(32);

    let mut tree_hashes = vec![Hash256::default(); SECTOR_SIZE / SEGMENT_SIZE];
    tree_hashes
        .par_chunks_exact_mut(4)
        .enumerate()
        .for_each(|(i, chunk)| {
            // prepare inputs
            let mut inputs = [[0u8; SEGMENT_SIZE + 1]; 4];
            for (j, input) in inputs.iter_mut().enumerate() {
                input[0] = LEAF_HASH_PREFIX[0];
                input[1..]
                    .copy_from_slice(&sector[SEGMENT_SIZE * (i + j)..SEGMENT_SIZE * (i + j + 1)]);
            }

            // hash them
            let mut jobs = [
                HashManyJob::new(&params, &inputs[0][..]),
                HashManyJob::new(&params, &inputs[1][..]),
                HashManyJob::new(&params, &inputs[2][..]),
                HashManyJob::new(&params, &inputs[3][..]),
            ];
            hash_many(&mut jobs);

            // collect results
            for j in 0..4 {
                chunk[j] = jobs[j].to_hash().into();
            }
        });

    let mut chunk_size = 4;
    while chunk_size <= tree_hashes.len() {
        tree_hashes.par_chunks_mut(chunk_size).for_each(|nodes| {
            // prepare inputs
            let mut inputs = [[0u8; 65]; 2];
            for (j, input) in inputs.iter_mut().enumerate() {
                input[0] = NODE_HASH_PREFIX[0];
                let step = j * chunk_size / 2;
                input[1..33].copy_from_slice(nodes[step].as_ref());
                input[33..65].copy_from_slice(nodes[step + chunk_size / 4].as_ref());
            }

            // hash them
            let mut jobs = [
                HashManyJob::new(&params, &inputs[0][..]),
                HashManyJob::new(&params, &inputs[1][..]),
            ];
            hash_many(&mut jobs);

            // collect results
            nodes[0] = jobs[0].to_hash().into();
            nodes[nodes.len() / 2] = jobs[1].to_hash().into();
        });
        chunk_size *= 2;
    }
    // hash last two nodes into roots
    sum_node(
        &params,
        &tree_hashes[0],
        &tree_hashes[tree_hashes.len() / 2],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sector_root() {
        let sector = vec![0u8; SECTOR_SIZE];
        let root = sector_root(&sector);
        assert_eq!(
            root,
            Hash256::parse_string(
                "50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c"
            )
            .unwrap()
        );
        println!("{root}");
    }
}
