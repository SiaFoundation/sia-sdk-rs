use crate::merkle::{self, Accumulator, LEAF_HASH_PREFIX, NODE_HASH_PREFIX, sum_leaf, sum_node};
use crate::rhp::{LEAVES_PER_SECTOR, SECTOR_SIZE, SEGMENT_SIZE};
use crate::types::Hash256;
use blake2b_simd::Params;
use blake2b_simd::many::{HashManyJob, hash_many};
use rayon::prelude::*;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncReadExt};

/// Calculates the Merkle root of a sector
pub fn sector_root(sector: &[u8]) -> Hash256 {
    assert_eq!(sector.len(), SECTOR_SIZE);
    let mut params = Params::new();
    params.hash_length(32);

    let mut tree_hashes = vec![Hash256::default(); LEAVES_PER_SECTOR];
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

#[derive(Debug, Error)]
pub enum ProofValidationError {
    #[error("Invalid proof length: expected {expected}, got {actual}")]
    InvalidProofLength { expected: usize, actual: usize },

    #[error("Invalid proof root: expected {expected}, got {actual}")]
    InvalidProofRoot { expected: Hash256, actual: Hash256 },

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("The proof data is not segment aligned")]
    NotSegmentAligned,
}

pub type Result<T> = std::result::Result<T, ProofValidationError>;

pub struct RangeProof;

impl RangeProof {
    #[allow(dead_code)]
    pub async fn verify<R: AsyncRead + Unpin>(
        r: R,
        root: &Hash256,
        proof: &[Hash256],
        start: usize,
        end: usize,
    ) -> Result<()> {
        let roots = Self::read_data(&mut io::BufReader::new(r), start, end).await?;

        if proof.len() != range_proof_size(LEAVES_PER_SECTOR, start, end) {
            return Err(ProofValidationError::InvalidProofLength {
                expected: range_proof_size(LEAVES_PER_SECTOR, start, end),
                actual: proof.len(),
            });
        }

        let consume = |acc: &mut Accumulator, roots: &[Hash256], i: usize, j: usize| {
            let mut roots = roots;
            let mut i = i;
            while i < j && !roots.is_empty() {
                let subtree_size = next_subtree_size(i, j);
                let height = subtree_size.checked_ilog2().expect("should not be None");
                acc.insert_node(&roots[0], height as usize);
                roots = &roots[1..];
                i += subtree_size;
            }
        };

        let mut acc = merkle::Accumulator::new();
        consume(&mut acc, proof, 0, start);
        consume(&mut acc, &roots, start, end);
        consume(&mut acc, proof, end, LEAVES_PER_SECTOR);

        if acc.root() != *root {
            return Err(ProofValidationError::InvalidProofRoot {
                expected: *root,
                actual: acc.root(),
            });
        }
        Ok(())
    }

    async fn read_data<R: AsyncRead + Unpin>(
        r: &mut R,
        start: usize,
        end: usize,
    ) -> Result<Vec<Hash256>> {
        assert!(start < end);
        let mut i = start;
        let j = end;
        let mut roots = Vec::new();

        while i < j {
            let subtree_size = next_subtree_size(i, j);
            let n = subtree_size * SEGMENT_SIZE;
            let mut r = r.take(n as u64);
            let root = sector_root_from_reader(&mut r).await?;
            roots.push(root);
            i += subtree_size;
        }
        Ok(roots)
    }
}

fn next_subtree_size(start: usize, end: usize) -> usize {
    assert!(start < end);
    let ideal = start.trailing_zeros();
    let max_size = (end - start)
        .checked_ilog2()
        .expect("should not be None since start < end");
    if ideal > max_size {
        return 1 << max_size;
    }
    1 << ideal
}

fn range_proof_size(leaves_per_sector: usize, start: usize, end: usize) -> usize {
    let left_hashes = start.count_ones() as usize;
    let path_mask = 1usize
        << ((end - 1) ^ (leaves_per_sector - 1))
            .checked_ilog2()
            .expect("should not be None ");
    let right_hashes = (!(end - 1) & path_mask).count_ones() as usize;
    left_hashes + right_hashes
}

async fn sector_root_from_reader<R: AsyncRead + Unpin>(r: &mut R) -> Result<Hash256> {
    let mut acc = merkle::Accumulator::new();
    let mut r = io::BufReader::new(r);

    let mut leaf = [0u8; SEGMENT_SIZE];
    loop {
        // read a leaf
        let mut bytes_read = 0;
        while bytes_read < leaf.len() {
            let n = r.read(&mut leaf[..bytes_read]).await?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }
        // if no bytes were read, we are done
        // if a full segment was read, we add the leaf
        // otherwise, we got a partial segment, which results in an error
        match bytes_read {
            0 => return Ok(acc.root()),
            SEGMENT_SIZE => {
                let h = sum_leaf(Params::new().hash_length(32), &leaf);
                acc.add_leaf(&h);
            }
            _ => {
                return Err(ProofValidationError::NotSegmentAligned);
            }
        }
    }
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
