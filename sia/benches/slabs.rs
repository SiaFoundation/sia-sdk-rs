use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngCore;
use sia::objects::{Downloader, Error as UploadError, HostDialer, Uploader};
use sia::rhp::{Host, SECTOR_SIZE, sector_root};
use sia::signing::{PrivateKey, PublicKey};
use sia::types::Hash256;
use tokio::runtime::Runtime;
use tokio::time::sleep;

#[derive(Debug, Clone)]
struct MockUploader {
    inner: Arc<MockUploaderInner>,
}

#[derive(Debug)]
struct MockUploaderInner {
    hosts: Mutex<HashMap<PublicKey, Host>>,
    sectors: Mutex<HashMap<Hash256, Vec<u8>>>,
}

impl MockUploader {
    fn new() -> Self {
        Self {
            inner: Arc::new(MockUploaderInner {
                hosts: Mutex::new(HashMap::new()),
                sectors: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl HostDialer for MockUploader {
    type Error = UploadError;

    async fn write_sector(
        &self,
        _: PublicKey,
        _: &PrivateKey,
        data: Vec<u8>,
    ) -> Result<Hash256, Self::Error> {
        let inner = self.inner.clone();
        let root = sector_root(data.as_ref());
        sleep(Duration::from_millis(10)).await;
        inner.sectors.lock().unwrap().insert(root, data);
        Ok(root)
    }

    async fn read_sector(
        &self,
        _: PublicKey,
        _: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let inner = self.inner.clone();
        sleep(Duration::from_millis(10)).await;
        let sector = inner.sectors.lock().unwrap().get(&root).unwrap().clone();
        Ok(sector[offset..offset + limit].to_vec())
    }

    fn hosts(&self) -> Vec<PublicKey> {
        self.inner.hosts.lock().unwrap().keys().cloned().collect()
    }

    fn update_hosts(&mut self, hosts: Vec<Host>) {
        let mut hosts_map = self.inner.hosts.lock().unwrap();
        hosts_map.clear();
        for host in hosts {
            hosts_map.insert(host.public_key, host);
        }
    }
}

fn benchmark_upload(c: &mut Criterion) {
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 20;
    const DATA_SIZE: usize = 4 * SECTOR_SIZE * DATA_SHARDS;

    let mut data = vec![0u8; DATA_SIZE];
    rand::rng().fill_bytes(&mut data);

    c.bench_with_input(BenchmarkId::new("upload", DATA_SIZE), &data, |b, data| {
        let rt = Runtime::new().expect("Failed to create runtime");

        let encryption_key: [u8; 32] = rand::random();
        b.to_async(rt).iter(|| async move {
            let mut uploader = MockUploader::new();
            uploader.update_hosts(
                (0..(DATA_SHARDS + PARITY_SHARDS))
                    .map(|_| Host {
                        public_key: PublicKey::new(rand::random()),
                        addresses: vec![],
                    })
                    .collect(),
            );

            let slab_uploader = Uploader::new(uploader, PrivateKey::from_seed(&[0u8; 32]), 30);

            let slabs = slab_uploader
                .upload(
                    &mut &data[..],
                    encryption_key,
                    DATA_SHARDS as u8,
                    PARITY_SHARDS as u8,
                )
                .await
                .expect("upload failed");

            assert_eq!(slabs.len(), 4);
        });
    });
}

fn benchmark_download(c: &mut Criterion) {
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 20;
    const DATA_SIZE: usize = 4 * SECTOR_SIZE * DATA_SHARDS;

    let mut data = vec![0u8; DATA_SIZE];
    rand::rng().fill_bytes(&mut data);

    let rt = Runtime::new().expect("Failed to create runtime");
    let encryption_key: [u8; 32] = rand::random();
    let uploader = MockUploader::new();

    let mut inner_upload = uploader.clone();
    let slabs = rt.block_on(async move {
        inner_upload.update_hosts(
            (0..(DATA_SHARDS + PARITY_SHARDS))
                .map(|_| Host {
                    public_key: PublicKey::new(rand::random()),
                    addresses: vec![],
                })
                .collect(),
        );

        let slab_uploader = Uploader::new(inner_upload, PrivateKey::from_seed(&[0u8; 32]), 30);

        slab_uploader
            .upload(
                &mut &data[..],
                encryption_key,
                DATA_SHARDS as u8,
                PARITY_SHARDS as u8,
            )
            .await
            .expect("upload failed")
    });
    c.bench_with_input(
        BenchmarkId::new("download", DATA_SIZE),
        &(uploader, slabs),
        |b, (uploader, slabs)| {
            let rt = Runtime::new().expect("Failed to create runtime");
            b.to_async(rt).iter(|| async move {
                let slab_downloader =
                    Downloader::new(uploader.clone(), PrivateKey::from_seed(&[0u8; 32]), 10);
                let mut downloaded_data = Vec::with_capacity(DATA_SIZE);
                slab_downloader
                    .download(&mut downloaded_data, slabs)
                    .await
                    .expect("failed to download");
            })
        },
    );
}

criterion_group!(benches, benchmark_upload, benchmark_download);
criterion_main!(benches);
