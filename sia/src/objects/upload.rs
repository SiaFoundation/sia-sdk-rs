use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;

use crate::objects::encryption::encrypt_shards;
use crate::objects::erasure_coding::{self, ErasureCoder};
use crate::objects::slabs::{Sector, Slab};
use crate::rhp::{self, Host};
use crate::signing::{PrivateKey, PublicKey};
use crate::types::Hash256;

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

    #[error("encoder error: {0}")]
    Encoder(#[from] erasure_coding::Error),
    #[error("not enough shards: {0}/{1}")]
    NotEnoughShards(u8, u8),

    #[error("no more hosts available")]
    NoMoreHosts,
    #[error("uploader closed")]
    Closed,
}

struct SlabUploader {
    account_key: PrivateKey,
    hosts: Mutex<VecDeque<Host>>,

    semaphore: Arc<Semaphore>,
}

impl SlabUploader {
    async fn write_sector(
        &self,
        dialer: &impl HostDialer,
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

                let res = dialer.write_sector(host.public_key, &self.account_key, sector).await?;
                Ok(Sector { root: res.root, host_key: host.public_key })
            }
        };

        let mut tasks = FuturesUnordered::new();
        tasks.push(start_upload(sector.as_ref().to_vec()));
        loop {
            tokio::select! {
                Some(res) = tasks.next() => {
                    match res {
                        Ok(sector) => {
                            return Ok(sector);
                        }
                        Err(_) => {
                            // try the next host
                            tasks.push(start_upload(sector.as_ref().to_vec()));
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    tasks.push(start_upload(sector.as_ref().to_vec()));
                }
            }
        }
    }
}

pub struct UploadOptions {
    pub encryption_key: [u8; 32],
    pub data_shards: u8,
    pub parity_shards: u8,
    pub max_inflight: usize,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            encryption_key: rand::random(),
            data_shards: 10,
            parity_shards: 20,
            max_inflight: 10,
        }
    }
}

pub async fn upload<R, D>(account_key: PrivateKey, dialer: &D, r: &mut R, options: &UploadOptions) -> Result<Vec<Slab>, Error>
where
R: AsyncReadExt + Unpin,
D: HostDialer {
    let mut slabs = Vec::new();
    let mut rs = ErasureCoder::new(options.data_shards as usize, options.parity_shards as usize)?;
    loop {
        let hosts = VecDeque::from(dialer.hosts());
        let slab_uploader = SlabUploader {
            account_key: account_key.clone(),
            hosts: Mutex::new(hosts),
            semaphore: Arc::new(Semaphore::new(options.max_inflight)),
        };
        let (mut shards, length) = rs.read_encoded_shards(r).await?;
        if length == 0 {
            break;
        }
        encrypt_shards(&options.encryption_key, &mut shards, 0);

        let mut futures = Vec::new();
        for shard in shards {
            futures.push(slab_uploader.write_sector(dialer, shard));
        }

        let results = try_join_all(futures).await?;
        slabs.push(Slab {
            encryption_key,
            min_shards: data_shards,
            sectors: results,
            offset: 0,
            length,
        });
    }
    Ok(slabs)
}

