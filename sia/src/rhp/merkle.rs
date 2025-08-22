use std::collections::VecDeque;

use crate::encoding_async::{AsyncSiaDecodable, AsyncSiaEncodable};
use crate::merkle::{self, Accumulator, LEAF_HASH_PREFIX, NODE_HASH_PREFIX, sum_leaf, sum_node};
use crate::rhp::{LEAVES_PER_SECTOR, SECTOR_SIZE, SEGMENT_SIZE};
use crate::types::Hash256;
use blake2b_simd::Params;
use blake2b_simd::many::{HashManyJob, hash_many};
use rayon::prelude::*;
use sia_derive::{AsyncSiaDecode, AsyncSiaEncode};
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

#[derive(Debug, AsyncSiaEncode, AsyncSiaDecode, PartialEq)]
pub struct RangeProof(Vec<Hash256>, Vec<u8>);

impl RangeProof {
    pub async fn verify(self, root: &Hash256, start: usize, end: usize) -> Result<Vec<u8>> {
        let mut roots: VecDeque<Hash256> = self.roots(start, end)?;
        let mut proof: VecDeque<Hash256> = self.0.into();

        if proof.len() != range_proof_size(LEAVES_PER_SECTOR, start, end) {
            return Err(ProofValidationError::InvalidProofLength {
                expected: range_proof_size(LEAVES_PER_SECTOR, start, end),
                actual: proof.len(),
            });
        }

        let consume = |acc: &mut Accumulator, roots: &mut VecDeque<Hash256>, i: usize, j: usize| {
            let mut i = i;
            while i < j
                && let Some(root) = roots.pop_front()
            {
                let subtree_size = next_subtree_size(i, j);
                let height = subtree_size.trailing_zeros(); // log2
                acc.insert_node(root, height as usize);
                i += subtree_size;
            }
        };

        let mut acc = merkle::Accumulator::new();
        consume(&mut acc, &mut proof, 0, start);
        consume(&mut acc, &mut roots, start, end);
        consume(&mut acc, &mut proof, end, LEAVES_PER_SECTOR);

        if acc.root() != *root {
            return Err(ProofValidationError::InvalidProofRoot {
                expected: *root,
                actual: acc.root(),
            });
        }
        Ok(self.1)
    }

    fn roots(&self, start: usize, end: usize) -> Result<VecDeque<Hash256>> {
        assert!(start < end);
        let mut i = start;
        let j = end;
        let mut roots = VecDeque::new();
        let mut params = Params::new();
        params.hash_length(32);

        let mut acc = merkle::Accumulator::new();
        let mut off: usize = 0;
        while i < j {
            acc.reset();

            let subtree_size = next_subtree_size(i, j);
            let n = subtree_size * SEGMENT_SIZE;

            let leaf_hashes: Vec<Hash256> = self
                .1
                .get(off..off + n)
                .ok_or(ProofValidationError::NotSegmentAligned)?
                .par_chunks_exact(64)
                .map(|segment| sum_leaf(&params, segment))
                .collect();

            for h in leaf_hashes {
                acc.add_leaf(h);
            }

            roots.push_back(acc.root());
            off += n;
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
    let path_mask = (1usize
        << ((end - 1) ^ (leaves_per_sector - 1))
            .checked_ilog2()
            .map(|n| n + 1)
            .unwrap_or(0))
        - 1;
    let right_hashes = (!(end - 1) & path_mask).count_ones() as usize;
    left_hashes + right_hashes
}

async fn sector_root_from_reader<R: AsyncRead + Unpin>(r: &mut R) -> Result<Hash256> {
    let mut acc = merkle::Accumulator::new();
    let r = r.take(SECTOR_SIZE as u64); // cap at a sector
    let mut r = io::BufReader::new(r);

    let mut leaf = [0u8; SEGMENT_SIZE];
    loop {
        // read a leaf
        let mut bytes_read = 0;
        while bytes_read < leaf.len() {
            let n = r.read(&mut leaf[bytes_read..]).await?;
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
                acc.add_leaf(h);
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

    #[test]
    fn test_range_proof_size() {
        assert_eq!(range_proof_size(LEAVES_PER_SECTOR, 0, LEAVES_PER_SECTOR), 0);
        assert_eq!(range_proof_size(LEAVES_PER_SECTOR, 1, LEAVES_PER_SECTOR), 1);
        assert_eq!(
            range_proof_size(LEAVES_PER_SECTOR, 0, LEAVES_PER_SECTOR / 2),
            1
        );
        assert_eq!(
            range_proof_size(
                LEAVES_PER_SECTOR,
                LEAVES_PER_SECTOR / 2,
                LEAVES_PER_SECTOR / 2
            ),
            2
        );
        assert_eq!(range_proof_size(LEAVES_PER_SECTOR, 0, 42), 13);
        assert_eq!(range_proof_size(LEAVES_PER_SECTOR, 24, 42), 15);
        assert_eq!(
            range_proof_size(LEAVES_PER_SECTOR, 24, LEAVES_PER_SECTOR),
            2
        );
    }

    #[test]
    fn test_next_subtree_size() {
        assert_eq!(next_subtree_size(0, 1), 1);
        assert_eq!(
            next_subtree_size(LEAVES_PER_SECTOR, LEAVES_PER_SECTOR + 1),
            1
        );
        assert_eq!(next_subtree_size(0, LEAVES_PER_SECTOR), 65536);
        assert_eq!(next_subtree_size(0, LEAVES_PER_SECTOR / 2), 32768);
        assert_eq!(
            next_subtree_size(LEAVES_PER_SECTOR / 2, LEAVES_PER_SECTOR),
            32768
        );
        assert_eq!(next_subtree_size(24, 42), 8);
    }

    #[tokio::test]
    async fn test_sector_root_from_reader() {
        // prepare slightly more than a sector worth of data to make sure we
        // only compute the hash over the first SECTOR_SIZE bytes
        let data = vec![0u8; SECTOR_SIZE + 64];
        let root = sector_root_from_reader(&mut &data[..]).await.unwrap();

        let expected_root =
            hash_256!("50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c");
        assert_eq!(root, expected_root);
    }

    #[tokio::test]
    async fn test_verify_range_proof() {
        let data = vec![0u8; SECTOR_SIZE];
        let sector_root = sector_root(&data);
        let proof: Vec<Hash256> = vec![
            hash_256!("f0022a573326ecc0e4c18cf56b9a31d94dc792f8ec20ecbbc57d33c75db24c54"),
            hash_256!("d66f6fce29310f5d2db0d2398e6d93b23c9fa1982b7249b07664590b7aebc49a"),
            hash_256!("5b3bc22a619574a668c4e2a22fa72210611813c6ed44cf445789ee316102bfe1"),
            hash_256!("3d8e644caa3e7ac720b1f7ce42d829ecf2c0ad7ef656258f4c1c90422074ba23"),
            hash_256!("f0022a573326ecc0e4c18cf56b9a31d94dc792f8ec20ecbbc57d33c75db24c54"),
            hash_256!("9213804e199cab3449185a5517f54e49c1d6b0892b8269ed4baab62dbf3e8ebb"),
            hash_256!("f052bf6db4444532ed0d8fdfc67c0ce9688fb4042d461a5bb367506de5e712a8"),
            hash_256!("61b3d824e7b4662df867477f09335dfecfc990c9f0b3731fbec981428b38190d"),
            hash_256!("272b122c6943a7dd6b5e2797a727de61f53c274f29d7d3e4e30d40620f83dc2b"),
            hash_256!("5ce18ab62a07bb4d4def2509f8bfa982d5cfd07deb533248abfd7b305652470c"),
            hash_256!("39cb8aa6feace01924b732664b81a8f41d688cbd7817154c663c1686a4cf6a0e"),
            hash_256!("95ab608799eb9c485712a4c995d4e22ea7b20024fe81730f5b4deb4982e97b78"),
            hash_256!("6530f5433504ba845332dd51742b57f0666456c99b78f67c72fac381980527b1"),
            hash_256!("53ae21d13da92c6741cf44e9b08e0c0616485402c343e4f6c92e5c8516187bcf"),
            hash_256!("f2c4d3e9ce380389b1088d44ddb30276fbff5f75803c2bd13678b690f4187d7e"),
        ];

        let verified_data = RangeProof(proof, data.clone()) // clone since RangeProof usually owns the data
            .verify(&sector_root, 24, 42)
            .await
            .expect("proof validation failed");
        assert_eq!(&data, &verified_data);
    }
}
