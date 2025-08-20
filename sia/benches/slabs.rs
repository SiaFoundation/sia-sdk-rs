use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngCore;
use sia::erasure_coding::ErasureCoder;
use sia::rhp::SECTOR_SIZE;
use sia::signing::PublicKey;
use sia::slabs::{Sector, SectorDownloader, SectorUploader, Slab};
use sia::types::Hash256;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

struct MockUploadDownloader {
    sectors: Mutex<HashMap<String, Vec<u8>>>,
}

impl SectorDownloader for MockUploadDownloader {
    async fn read_sector(
        &self,
        _: &PublicKey,
        root: &Hash256,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<u8>, sia::rhp::Error> {
        let sectors = self.sectors.lock().await;
        match sectors.get(&root.to_string()) {
            Some(data) => Ok(data[offset..offset + limit].to_vec()),
            None => Err(sia::rhp::Error::Transport("sector not found".into())),
        }
    }
}

impl SectorUploader for MockUploadDownloader {
    async fn write_sector(&self, sector: impl AsRef<[u8]>) -> Result<Sector, sia::rhp::Error> {
        let root = Hash256::new(rand::random());
        let sector_data = sector.as_ref().to_vec();
        let mut sectors = self.sectors.lock().await;
        sectors.insert(root.to_string(), sector_data);

        Ok(Sector {
            root,
            host_key: PublicKey::new(rand::random()),
        })
    }
}

fn benchmark_upload_slab(c: &mut Criterion) {
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 20;

    let mut data = vec![0u8; SECTOR_SIZE * DATA_SHARDS];
    rand::rng().fill_bytes(&mut data);
    let encryption_key: [u8; 32] = rand::random();

    c.bench_with_input(BenchmarkId::new("slabs", data.len()), &data, |b, data| {
        let rt = Runtime::new().expect("Failed to create runtime");
        b.to_async(rt).iter(|| async move {
            let uploader = MockUploadDownloader {
                sectors: Mutex::new(HashMap::new()),
            };
            Slab::upload(
                &mut data.as_ref(),
                &uploader,
                encryption_key,
                DATA_SHARDS as u8,
                PARITY_SHARDS as u8,
            )
            .await
            .expect("Failed to upload slab");
        });
    });
}

fn benchmark_erasure_code(c: &mut Criterion) {
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 20;

    let mut data = vec![0u8; SECTOR_SIZE * DATA_SHARDS];
    rand::rng().fill_bytes(&mut data);

    c.bench_with_input(
        BenchmarkId::new("erasure_code", data.len()),
        &data,
        |b, data| {
            let rt = Runtime::new().expect("Failed to create runtime");
            b.to_async(rt).iter(|| async move {
                let mut enc = ErasureCoder::new(DATA_SHARDS, PARITY_SHARDS)
                    .expect("Failed to create erasure coder");
                enc.read_encoded_shards(&mut data.as_ref())
                    .await
                    .expect("Failed to read encoded shards");
            });
        },
    );
}

criterion_group!(benches, benchmark_upload_slab, benchmark_erasure_code);
criterion_main!(benches);
