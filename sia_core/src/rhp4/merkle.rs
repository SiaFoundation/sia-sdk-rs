use std::collections::VecDeque;

use super::{LEAVES_PER_SECTOR, SECTOR_SIZE, SEGMENT_SIZE};
use crate::encoding::{SiaDecodable, SiaDecode, SiaEncodable, SiaEncode};
use crate::encoding_async::AsyncSiaDecode;
use crate::merkle::{self, Accumulator};
use crate::types::Hash256;
use bytes::Bytes;
use thiserror::Error;
use tokio::io::{self};

/// Calculates the Merkle root of a sector
pub fn sector_root(sector: &[u8]) -> Hash256 {
    assert_eq!(sector.len(), SECTOR_SIZE);

    let mut nodes = vec![[0u8; 32]; LEAVES_PER_SECTOR];
    merkle::hash_leaves_many(&mut nodes, merkle::as_blocks(sector));

    while nodes.len() > 1 {
        let mut parents = vec![[0u8; 32]; nodes.len() / 2];
        merkle::hash_nodes_many(&mut parents, &nodes);
        nodes = parents;
    }
    nodes[0].into()
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

#[derive(Debug, SiaEncode, SiaDecode, AsyncSiaDecode, PartialEq)]
pub struct RangeProof(Vec<Hash256>, Bytes);

impl RangeProof {
    pub fn verify(
        self,
        root: &Hash256,
        start: usize,
        end: usize,
    ) -> Result<Bytes, ProofValidationError> {
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

    fn roots(&self, start: usize, end: usize) -> Result<VecDeque<Hash256>, ProofValidationError> {
        assert!(start < end);

        let total = (end - start) * SEGMENT_SIZE;
        let data = self
            .1
            .get(..total)
            .ok_or(ProofValidationError::NotSegmentAligned)?;

        let mut leaf_hashes = vec![[0u8; 32]; end - start];
        merkle::hash_leaves_many(&mut leaf_hashes, merkle::as_blocks(data));

        let mut roots = VecDeque::new();
        let mut acc = merkle::Accumulator::new();
        let mut leaves = leaf_hashes.into_iter();
        let mut i = start;
        let j = end;
        while i < j {
            acc.reset();
            let subtree_size = next_subtree_size(i, j);
            for _ in 0..subtree_size {
                acc.add_leaf(leaves.next().expect("leaf count matches range").into());
            }
            roots.push_back(acc.root());
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

    fn random_sector() -> Vec<u8> {
        const SECTOR_SEED: u64 = 0x0123456789abcdef;

        let mut sector = vec![0u8; SECTOR_SIZE];
        crate::test_util::fill(SECTOR_SEED, &mut sector);
        sector
    }

    // Proof vectors are golden, from go.sia.tech/core rhp/v2.BuildProof.
    fn sector_proof_24_42() -> (Vec<Hash256>, Bytes, Hash256) {
        let sector = random_sector();
        let root = sector_root(&sector);
        let data = Bytes::copy_from_slice(&sector[24 * SEGMENT_SIZE..42 * SEGMENT_SIZE]);
        let proof = vec![
            hash_256!("9596ec473dc28ec9ed9f40aff5023d724447584e2229d64b252bad1882d346f3"),
            hash_256!("e28c4f2c253195bd718757a7d3f7015cef60f570b2dc19cad1508c219b1c0495"),
            hash_256!("13162b01bcbd53f56ee3090431c274b43194009ab037dd2f8fc6fcce69b85d2d"),
            hash_256!("e9bf7f6b9e17c0942e34d50b6851419fc64d7e8bde24b50334ac58c6d53d4f81"),
            hash_256!("4168077910d52f8694b0084d45a4b22db0f497984e95b29bb47a82c0e8b249bb"),
            hash_256!("a17f44317bd8647db096d6cc3080428de8cea4caf391cbcf8d39bc683970962f"),
            hash_256!("2c1262b5c876c9616e738f32948d5b0621dd4eb7058c760f0669d364bed69027"),
            hash_256!("28c7e0115673a315b1fa5b21a29d79e156fe1a627b0d8228f08cd0f7ca5e674d"),
            hash_256!("ff5657a7b775b6d95a43d66b7cdf0241e624f459f861176c3e5dacde9876d98d"),
            hash_256!("d01cf598e2582f186359ff260e48bce40f9279105c66077d59a456bdd2d0f4ec"),
            hash_256!("c07d4d530161f9adfe5eb862af5dd7edc4fa8eb0310fcb25ef7eb51ede7b1e3a"),
            hash_256!("206fea02d289dd4205cea7032693f9253d5bff89e6019157dedf8b6ddc057b95"),
            hash_256!("d1896e9cbb9b49f9d6d9b8ccf6c14fe6466edd7c39e1beb3973783e7595d4e15"),
            hash_256!("8b21c694a70ac9302bd5b5523c5efb34d69e09835b93bfd36da018d5f6f2ab42"),
            hash_256!("c8a63e994d8d16fdb1a169f1baea63b1e7aa5cd29dd418e2eaa5427b85761d6a"),
        ];
        (proof, data, root)
    }

    #[test]
    fn test_verify_range_proof() {
        let (proof, data, root) = sector_proof_24_42();
        let verified_data = RangeProof(proof, data.clone())
            .verify(&root, 24, 42)
            .expect("proof validation failed");
        assert_eq!(&data, &verified_data);
    }

    #[test]
    fn test_verify_range_proof_rejects_tampered_proof() {
        let (mut proof, data, root) = sector_proof_24_42();
        proof[0] = Hash256::default();
        let err = RangeProof(proof, data)
            .verify(&root, 24, 42)
            .expect_err("a tampered proof must be rejected");
        assert!(matches!(err, ProofValidationError::InvalidProofRoot { .. }));
    }

    #[test]
    fn test_verify_range_proof_rejects_wrong_root() {
        let (proof, data, _) = sector_proof_24_42();
        let err = RangeProof(proof, data)
            .verify(&Hash256::default(), 24, 42)
            .expect_err("verification against the wrong root must fail");
        assert!(matches!(err, ProofValidationError::InvalidProofRoot { .. }));
    }

    #[test]
    fn test_verify_range_proof_rejects_wrong_length() {
        let (mut proof, data, root) = sector_proof_24_42();
        proof.push(Hash256::default());
        let err = RangeProof(proof, data)
            .verify(&root, 24, 42)
            .expect_err("a wrong-length proof must be rejected");
        assert!(matches!(
            err,
            ProofValidationError::InvalidProofLength {
                expected: 15,
                actual: 16
            }
        ));
    }

    #[test]
    fn test_verify_range_proof_rejects_short_data() {
        let (proof, _, root) = sector_proof_24_42();
        let short = Bytes::from(vec![0u8; 100]);
        let err = RangeProof(proof, short)
            .verify(&root, 24, 42)
            .expect_err("insufficient range data must be rejected");
        assert!(matches!(err, ProofValidationError::NotSegmentAligned));
    }

    #[test]
    fn test_verify_range_proof_first_leaf() {
        let sector = random_sector();
        let root = sector_root(&sector);
        let leaf = Bytes::copy_from_slice(&sector[..SEGMENT_SIZE]);
        let proof = vec![
            hash_256!("8550799550a2e7a81b99c4d8822380edc6f1e1aad34ce186f7e73449833efe51"),
            hash_256!("8efc5ed40031e486aad5927ac2dd0fe5540f420d93565c56daa415d92b2bd83f"),
            hash_256!("076e6419baca3cc9949dcd0e84f6b23fbd029b8cf4579b49f11d6d00767d2491"),
            hash_256!("fb59d0ffbe76c218a0a6c34337198137c1d9300552696804e15de865de994b50"),
            hash_256!("af28f37b51e5ae1a920dbf0e4121508e8677a9ddecfdf5d4c107bae8ab16dac0"),
            hash_256!("b983f8ed5c3f70589b7c2d34f65c93ac714cfbf1eca619355eeacd2923abed9d"),
            hash_256!("a17f44317bd8647db096d6cc3080428de8cea4caf391cbcf8d39bc683970962f"),
            hash_256!("2c1262b5c876c9616e738f32948d5b0621dd4eb7058c760f0669d364bed69027"),
            hash_256!("28c7e0115673a315b1fa5b21a29d79e156fe1a627b0d8228f08cd0f7ca5e674d"),
            hash_256!("ff5657a7b775b6d95a43d66b7cdf0241e624f459f861176c3e5dacde9876d98d"),
            hash_256!("d01cf598e2582f186359ff260e48bce40f9279105c66077d59a456bdd2d0f4ec"),
            hash_256!("c07d4d530161f9adfe5eb862af5dd7edc4fa8eb0310fcb25ef7eb51ede7b1e3a"),
            hash_256!("206fea02d289dd4205cea7032693f9253d5bff89e6019157dedf8b6ddc057b95"),
            hash_256!("d1896e9cbb9b49f9d6d9b8ccf6c14fe6466edd7c39e1beb3973783e7595d4e15"),
            hash_256!("8b21c694a70ac9302bd5b5523c5efb34d69e09835b93bfd36da018d5f6f2ab42"),
            hash_256!("c8a63e994d8d16fdb1a169f1baea63b1e7aa5cd29dd418e2eaa5427b85761d6a"),
        ];
        let verified = RangeProof(proof, leaf.clone())
            .verify(&root, 0, 1)
            .expect("first-leaf proof must verify");
        assert_eq!(&leaf, &verified);
    }

    #[test]
    fn test_verify_range_proof_last_leaf() {
        let sector = random_sector();
        let root = sector_root(&sector);
        let leaf = Bytes::copy_from_slice(&sector[(LEAVES_PER_SECTOR - 1) * SEGMENT_SIZE..]);
        let proof = vec![
            hash_256!("96f13920f86d041f75219a0d4366792cda5108c7288dbbf11b1b0a25ed8dfded"),
            hash_256!("655701359abe8ae8db16a354033d7f50b56763380229f2e1bfc42361bd8f1306"),
            hash_256!("aa2facdc65c75e2b40f046c667cbce9d85fc33e5dcc826636047ac21e946e91b"),
            hash_256!("d8e9facb499f9fe86425f15050090baa43e8ff8d1d345203bd53eb59e542cfc2"),
            hash_256!("21d5dce0cb524ba04cd773a31237f49b553201693074147dce48c4f355b3abd0"),
            hash_256!("bf6adda2756b1c669e6742a43470e2e918e134c730e007d706a3ca58fe568e51"),
            hash_256!("5c87a42f3ab69ef8e76c6175c9059ccbd3e9b11e39162384cb507c2d3f4e069e"),
            hash_256!("3831ae99af721b392b8ae1030b2868737731be0d4ee6eb0e12e0c2eaa8f08015"),
            hash_256!("112ee512b1e0d0f565ee60023613f19598ee8253c535ba59668233dc13f14e5a"),
            hash_256!("652d6ffedd4b3a73c7093693c854f894be21d6c8fd20df7e69c2f2982683e8ca"),
            hash_256!("9eeb76d680303180161abfc26ba06fd06702ba35828232c78d6b9ee186fe01f6"),
            hash_256!("d8e8d7145a2eedf5d4a1d003c44ac034e2299be9978fc1b5e77a0353b0049869"),
            hash_256!("9da31df94a2c2b41a7e33bc3191045a36664edc6868f4e5e1bff806c8cfbae16"),
            hash_256!("dd456d31603bc8810eeafb6653000a8487459b11f2019568b5de13d62cdeae64"),
            hash_256!("4517d881a2ed6e8bd1614609128206a34214b4acbe27e580e1c74b78db0b73d0"),
            hash_256!("10718bfa13e66cf96762749b3848edafe7ac7e47d0a5f13260c9e9badbb56a15"),
        ];
        let verified = RangeProof(proof, leaf.clone())
            .verify(&root, LEAVES_PER_SECTOR - 1, LEAVES_PER_SECTOR)
            .expect("last-leaf proof must verify");
        assert_eq!(&leaf, &verified);
    }

    #[test]
    fn test_verify_full_range_proof() {
        let sector = random_sector();
        let root = sector_root(&sector);
        let data = Bytes::from(sector);
        let verified_data = RangeProof(vec![], data.clone())
            .verify(&root, 0, LEAVES_PER_SECTOR)
            .expect("proof validation failed");
        assert_eq!(&data, &verified_data);
    }
}
