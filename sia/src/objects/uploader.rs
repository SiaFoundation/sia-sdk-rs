use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::StreamExt;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

use crate::objects::slabs::{Sector, Slab};
use crate::rhp::{self, Host};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;

pub trait SectorUploader {
    fn write_sector(
        &self,
        sector: impl AsRef<[u8]>,
    ) -> impl Future<Output = Result<Sector, Error>>;
}

pub trait SectorDownloader {
    fn read_sector(
        &self,
        host: &PublicKey,
        root: &Hash256,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>>;
}

pub trait HostDialer {
    fn write_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        sector: Vec<u8>,
    ) -> impl Future<Output = Result<Sector, Error>>;

    fn read_sector(
        &self,
        host_key: PublicKey,
        account_key: &PrivateKey,
        root: Hash256,
        offset: usize,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>>;

    fn hosts(&self) -> Vec<Host>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("dialer error: {0}")]
    Dialer(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("RHP error: {0}")]
    RPC(#[from] rhp::Error),

    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("uploader closed")]
    Closed,
}

struct SlabUploader<D: HostDialer> {
    dialer: D,
    account_key: PrivateKey,
    hosts: Mutex<VecDeque<Host>>,

    semaphore: Arc<Semaphore>,
}

impl<D: HostDialer> SectorUploader for SlabUploader<D> {
    async fn write_sector(
        &self,
        sector: impl AsRef<[u8]>,
    ) -> Result<Sector, Error> {
        let start_upload = |sector: Vec<u8>| {
            async move {
                let permit = self.semaphore.acquire().await;
                if !permit.is_ok() {
                    return Err(Error::Closed);
                }
                let host = self.hosts.lock().unwrap().pop_front();
                if host.is_none() {
                    return Err(Error::NoMoreHosts);
                }
                let host = host.unwrap();

                let res = self.dialer.write_sector(host.public_key, &self.account_key, sector).await?;
                Ok(Sector { root: res.root, host_key: host.public_key })
            }
        };

        let mut tasks = FuturesUnordered::new();
        tasks.push(start_upload(sector.as_ref().to_vec()));
        loop {
            tokio::select! {
                Some(res) = tasks.next() => {
                    return res;
                },
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    tasks.push(start_upload(sector.as_ref().to_vec()));
                }
            }
        }
    }
}

pub async fn upload<R, D>(account_key: PrivateKey, dialer: D, reader: &mut R, encryption_key: [u8;32], data_shards: u8, parity_shards: u8, max_inflight: usize) -> Result<Vec<Slab>, Error>
where
R: AsyncReadExt + Unpin,
D: HostDialer {
    let mut futures = FuturesOrdered::new();
    loop {
        futures.push_back(async move{
            let hosts = VecDeque::from(dialer.hosts());
            let slab_uploader = SlabUploader{
                dialer: dialer,
                account_key,
                hosts: Mutex::new(hosts),
                semaphore: Arc::new(Semaphore::new(max_inflight)),
            };
            Slab::upload(reader, &slab_uploader, encryption_key, data_shards, parity_shards)
        });
    }
    Ok(vec![])
}
