//! A stored sector with every level of its Merkle tree, so that a range
//! proof is a list of lookups.

use blake2b_simd::Params;
use bytes::Bytes;
use sia_core::rhp4::{LEAVES_PER_SECTOR, SECTOR_SIZE, SEGMENT_SIZE};
use sia_core::types::Hash256;

pub struct Sector {
    data: Bytes,
    /// Leaves first, the root last.
    levels: Vec<Vec<Hash256>>,
}

impl Sector {
    pub fn new(data: Bytes) -> Self {
        assert_eq!(data.len(), SECTOR_SIZE);
        let leaves = data
            .as_chunks::<SEGMENT_SIZE>()
            .0
            .iter()
            .map(|segment| hash(0, segment, &[]))
            .collect();
        let mut levels: Vec<Vec<Hash256>> = vec![leaves];
        while let [.., level] = levels.as_slice()
            && level.len() > 1
        {
            let next = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, right]| hash(1, left.as_ref(), right.as_ref()))
                .collect();
            levels.push(next);
        }
        Self { data, levels }
    }

    pub fn root(&self) -> Hash256 {
        self.levels[self.levels.len() - 1][0]
    }

    /// The segments covering `length` bytes at `offset`, and the roots of
    /// the subtrees covering every other segment, in the order the SDK
    /// verifies them.
    pub fn read(&self, offset: usize, length: usize) -> (Vec<Hash256>, Bytes) {
        let start = offset / SEGMENT_SIZE;
        let end = (offset + length).div_ceil(SEGMENT_SIZE);
        let mut proof = Vec::new();
        for (mut i, j) in [(0, start), (end, LEAVES_PER_SECTOR)] {
            while i < j {
                let size: usize = 1 << i.trailing_zeros().min((j - i).ilog2());
                let height = size.trailing_zeros() as usize;
                proof.push(self.levels[height][i >> height]);
                i += size;
            }
        }
        let data = self.data.slice(start * SEGMENT_SIZE..end * SEGMENT_SIZE);
        (proof, data)
    }
}

fn hash(prefix: u8, left: &[u8], right: &[u8]) -> Hash256 {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(&[prefix])
        .update(left)
        .update(right)
        .finalize();
    <[u8; 32]>::try_from(hash.as_bytes()).unwrap().into()
}

#[cfg(test)]
mod test {
    use sia_core::encoding::SiaEncodable;
    use sia_core::rhp4::protocol::RPCReadSector;
    use sia_core::rhp4::{AccountToken, HostPrices};
    use sia_core::signing::PrivateKey;
    use sia_core::types::Currency;

    use super::*;

    #[tokio::test]
    async fn test_reads_verify_in_sia_core() {
        let data: Bytes = (0..SECTOR_SIZE).map(|i| (i % 251) as u8).collect();
        let sector = Sector::new(data.clone());
        assert_eq!(sector.root(), sia_core::rhp4::sector_root(&data));

        let key = PrivateKey::from_seed(&[0; 32]);
        let prices = HostPrices {
            contract_price: Currency::new(0),
            collateral: Currency::new(0),
            storage_price: Currency::new(0),
            ingress_price: Currency::new(0),
            egress_price: Currency::new(0),
            free_sector_price: Currency::new(0),
            tip_height: 0,
            valid_until: chrono::Utc::now(),
            signature: Default::default(),
        };
        for (offset, length) in [(0, 64), (100, 300), (4096, 1 << 20), (SECTOR_SIZE - 64, 64)] {
            let (proof, segments) = sector.read(offset, length);
            let mut response = Vec::new();
            false.encode(&mut response).unwrap();
            proof.encode(&mut response).unwrap();
            segments.encode(&mut response).unwrap();

            let token = AccountToken::new(&key, key.public_key());
            let rpc = RPCReadSector::send_request(
                &mut Vec::new(),
                prices.clone(),
                token,
                sector.root(),
                offset,
                length,
            )
            .await
            .unwrap();
            let read = rpc.complete(&mut &response[..]).await.unwrap();
            assert_eq!(read.data, data[offset..offset + length]);
        }
    }
}
