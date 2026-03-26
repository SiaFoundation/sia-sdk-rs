//! WebTransport-based RHP4 client for WASM targets.
//!
//! This module will provide a [`Client`] that implements [`super::Transport`]
//! using the browser's WebTransport API, mirroring the siamux client on native.
//!
//! TODO: implement WebTransport connection pooling and RPC methods.
use async_trait::async_trait;
use bytes::Bytes;
use sia_core::rhp4::HostPrices;
use sia_core::signing::PrivateKey;
use sia_core::types::Hash256;

use super::{Error, HostEndpoint};

#[derive(Clone, Debug, Default)]
pub struct Client;

impl Client {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl super::Transport for Client {
    async fn host_prices(&self, _host: &HostEndpoint) -> Result<HostPrices, Error> {
        todo!("WebTransport host_prices not yet implemented")
    }

    async fn write_sector(
        &self,
        _host: &HostEndpoint,
        _prices: HostPrices,
        _account_key: &PrivateKey,
        _sector: Bytes,
    ) -> Result<Hash256, Error> {
        todo!("WebTransport write_sector not yet implemented")
    }

    async fn read_sector(
        &self,
        _host: &HostEndpoint,
        _prices: HostPrices,
        _account_key: &PrivateKey,
        _root: Hash256,
        _offset: usize,
        _length: usize,
    ) -> Result<Bytes, Error> {
        todo!("WebTransport read_sector not yet implemented")
    }
}
