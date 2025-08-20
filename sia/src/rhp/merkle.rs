use crate::merkle::{LEAF_HASH_PREFIX, NODE_HASH_PREFIX, sum_node};
use crate::rhp::{SECTOR_SIZE, SEGMENT_SIZE};
use crate::types::Hash256;
use blake2b_simd::Params;
use blake2b_simd::many::{HashManyJob, hash_many};
use rayon::prelude::*;

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
                let start = i * 4 + j;
                let end = start + 1;
                input[0] = LEAF_HASH_PREFIX[0];
                input[1..].copy_from_slice(&sector[SEGMENT_SIZE * start..SEGMENT_SIZE * end]);
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
    use crate::hash_256;

    #[test]
    fn test_sector_root() {
        let mut sector = vec![0u8; SECTOR_SIZE];
        let root = sector_root(&sector);
        assert_eq!(
            root,
            hash_256!("50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c")
        );

        sector[0] = 1;
        let root = sector_root(&sector);
        assert_eq!(
            root,
            hash_256!("8c20a2c90a733a5139cc57e45755322e304451c3434b0c0a0aad87f2f89a44ab")
        );

        sector[0] = 0;
        sector[SECTOR_SIZE - 1] = 1;
        let root = sector_root(&sector);
        assert_eq!(
            root,
            hash_256!("d0ab6691d76750618452e920386e5f6f98fdd1219a70a06f06ef622ac6c6373c")
        );

        sector
            .iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = (i % 256) as u8);
        let root = sector_root(&sector);
        assert_eq!(
            root,
            hash_256!("84d0672b204f38469dbb818bcb3caa7391f7781cbf84bce0482b2fd2c2d50938")
        );
    }
}
