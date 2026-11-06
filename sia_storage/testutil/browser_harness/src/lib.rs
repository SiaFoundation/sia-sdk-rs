//! The control API of the fake hosts that the `sia_storage` browser tests
//! run against. The binary serves it, and the tests call it through
//! `Harness`, which exists only in WASM builds, to set up each host.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sia_core::signing::PublicKey;

/// Where the binary serves the control API. The address is fixed, so only
/// one run at a time fits on a machine.
pub const CONTROL_ADDR: &str = "127.0.0.1:48650";

/// How a host answers a WebTransport handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Handshake {
    #[default]
    Accept,
    /// Completes QUIC but answers the WebTransport request with 404, so the
    /// session's `ready` rejects.
    Refuse,
    /// Never answers, like a host behind a firewall that drops UDP. Chrome
    /// gives up when its QUIC handshake times out. A host can't switch to or
    /// from this after it starts.
    Ignore,
}

/// How a host behaves. It can change while the host runs, and the host keeps
/// its key and address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostSpec {
    pub handshake: Handshake,
    /// Wait this long before answering a WebTransport request.
    pub handshake_delay: Duration,
    /// Wait this long before answering a sector read.
    pub read_delay: Duration,
    /// Judge account tokens as if the host's clock ran this far ahead.
    pub clock_ahead: Duration,
    /// Answer writes without storing the sector, so reads of it fail. For
    /// uploads too large to hold in memory.
    pub discard_sectors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeHost {
    pub public_key: PublicKey,
    pub address: SocketAddr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStats {
    /// WebTransport requests received since the host started.
    pub handshakes: u64,
    /// WebTransport sessions accepted since the host started.
    pub sessions: u64,
    /// Streams open now.
    pub open_streams: u64,
    /// Settings RPCs since the host started.
    pub settings: u64,
    /// Reads and writes refused for an expired account token since the host
    /// started.
    pub expired_tokens: u64,
}

#[cfg(target_arch = "wasm32")]
pub use client::Harness;

#[cfg(target_arch = "wasm32")]
mod client {
    use serde::de::DeserializeOwned;

    use super::{CONTROL_ADDR, FakeHost, HostSpec, HostStats};

    /// A client for the control API.
    pub struct Harness {
        http: reqwest::Client,
        url: String,
    }

    impl Default for Harness {
        fn default() -> Self {
            Self {
                http: reqwest::Client::new(),
                url: format!("http://{CONTROL_ADDR}"),
            }
        }
    }

    impl Harness {
        /// Replaces every host with new ones, which have new keys and ports.
        pub async fn reset(&self, specs: &[HostSpec]) -> Vec<FakeHost> {
            self.call(self.http.post(format!("{}/hosts", self.url)).json(specs))
                .await
        }

        /// Changes how host `index` behaves.
        pub async fn set(&self, index: usize, spec: &HostSpec) {
            self.call(
                self.http
                    .put(format!("{}/hosts/{index}", self.url))
                    .json(spec),
            )
            .await
        }

        /// Each host's stats, in the order [`Harness::reset`] returned them.
        pub async fn stats(&self) -> Vec<HostStats> {
            self.call(self.http.get(format!("{}/stats", self.url)))
                .await
        }

        async fn call<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> T {
            let response = request
                .send()
                .await
                .unwrap_or_else(|e| panic!("browser_harness at {} did not answer: {e}", self.url));
            let status = response.status();
            if !status.is_success() {
                panic!(
                    "browser_harness: {status} {}",
                    response.text().await.unwrap_or_default()
                );
            }
            response.json().await.expect("browser_harness response")
        }
    }
}
