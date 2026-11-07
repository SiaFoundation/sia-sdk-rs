//! A fake host. It answers the three RPCs the SDK's WebTransport client
//! sends (Settings, WriteSector and ReadSector) in the format a real host
//! uses, and behaves as its [`HostSpec`] says.

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::fixtures::{FakeHost, Handshake, HostSpec, HostStats};
use chrono::Utc;
use sia_core::encoding::SiaEncodable;
use sia_core::encoding_async::AsyncSiaDecodable;
use sia_core::rhp4::protocol::RPCError;
use sia_core::rhp4::{AccountToken, HostPrices, HostSettings, SECTOR_SIZE, sector_root};
use sia_core::signing::PrivateKey;
use sia_core::types::{Address, Currency, Hash256, Specifier};
use tokio::task::JoinHandle;
use wtransport::endpoint::IncomingSession;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::{Endpoint, Identity, RecvStream, SendStream, ServerConfig};

use crate::sector::Sector;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Host {
    pub info: FakeHost,
    state: Arc<State>,
    listener: Listener,
}

enum Listener {
    Serving {
        endpoint: Arc<Endpoint<Server>>,
        accepting: JoinHandle<()>,
    },
    /// A bound socket nothing reads, so packets to the port go unanswered.
    Ignoring { _socket: UdpSocket },
}

struct State {
    key: PrivateKey,
    spec: RwLock<HostSpec>,
    counters: Counters,
    sectors: Mutex<HashMap<Hash256, Arc<Sector>>>,
}

#[derive(Default)]
struct Counters {
    handshakes: AtomicU64,
    sessions: AtomicU64,
    open_streams: AtomicU64,
    settings: AtomicU64,
    expired_tokens: AtomicU64,
}

impl Host {
    pub fn start(spec: HostSpec, identity: &Identity) -> Result<Self, Error> {
        let ignoring = spec.handshake == Handshake::Ignore;
        let state = Arc::new(State {
            key: PrivateKey::from_seed(&rand::random()),
            spec: RwLock::new(spec),
            counters: Counters::default(),
            sectors: Mutex::default(),
        });
        let (listener, port) = if ignoring {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = socket.local_addr()?.port();
            (Listener::Ignoring { _socket: socket }, port)
        } else {
            let endpoint = Arc::new(Endpoint::server(
                ServerConfig::builder()
                    .with_bind_address((Ipv4Addr::LOCALHOST, 0).into())
                    .with_identity(identity.clone_identity())
                    // Keeps sessions open while they sit idle between a
                    // test's steps.
                    .keep_alive_interval(Some(Duration::from_secs(3)))
                    .build(),
            )?);
            let port = endpoint.local_addr()?.port();
            let accepting = tokio::spawn({
                let endpoint = endpoint.clone();
                let state = state.clone();
                async move {
                    loop {
                        let incoming = endpoint.accept().await;
                        tokio::spawn(serve_session(state.clone(), incoming));
                    }
                }
            });
            (
                Listener::Serving {
                    endpoint,
                    accepting,
                },
                port,
            )
        };
        Ok(Self {
            info: FakeHost {
                public_key: state.key.public_key(),
                address: ([127, 0, 0, 1], port).into(),
            },
            state,
            listener,
        })
    }

    pub async fn stop(self) {
        if let Listener::Serving {
            endpoint,
            accepting,
        } = self.listener
        {
            accepting.abort();
            endpoint.close(0u32.into(), b"host stopped");
            endpoint.wait_idle().await;
        }
    }

    pub fn set(&self, spec: HostSpec) -> Result<(), Error> {
        let mut current = self.state.spec.write().unwrap();
        if (current.handshake == Handshake::Ignore) != (spec.handshake == Handshake::Ignore) {
            return Err("a host can't switch to or from ignoring handshakes".into());
        }
        *current = spec;
        Ok(())
    }

    pub fn stats(&self) -> HostStats {
        let c = &self.state.counters;
        HostStats {
            handshakes: c.handshakes.load(Ordering::Relaxed),
            sessions: c.sessions.load(Ordering::Relaxed),
            open_streams: c.open_streams.load(Ordering::Relaxed),
            settings: c.settings.load(Ordering::Relaxed),
            expired_tokens: c.expired_tokens.load(Ordering::Relaxed),
        }
    }
}

async fn serve_session(state: Arc<State>, incoming: IncomingSession) {
    let Ok(request) = incoming
        .await
        .inspect_err(|err| eprintln!("WebTransport handshake failed: {err}"))
    else {
        return;
    };
    state.counters.handshakes.fetch_add(1, Ordering::Relaxed);
    let spec = state.spec.read().unwrap().clone();
    tokio::time::sleep(spec.handshake_delay).await;
    if request.path() != "/sia/rhp/v4" || spec.handshake == Handshake::Refuse {
        request.not_found().await;
        return;
    }
    let Ok(connection) = request
        .accept()
        .await
        .inspect_err(|err| eprintln!("WebTransport session failed: {err}"))
    else {
        return;
    };
    state.counters.sessions.fetch_add(1, Ordering::Relaxed);
    while let Ok((send, recv)) = connection.accept_bi().await {
        let state = state.clone();
        tokio::spawn(async move {
            state.counters.open_streams.fetch_add(1, Ordering::Relaxed);
            // Most errors are streams the client cancelled, as it does to
            // every read that loses a race, so they are not logged.
            let _ = serve_stream(&state, send, recv).await;
            state.counters.open_streams.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn serve_stream(
    state: &State,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Error> {
    let rpc = Specifier::decode_async(&mut recv).await?.to_string();
    let spec = state.spec.read().unwrap().clone();
    let result = match rpc.as_str() {
        "Settings" => {
            state.counters.settings.fetch_add(1, Ordering::Relaxed);
            Ok(encode(&settings(&state.key)))
        }
        "WriteSector" => {
            let _prices = HostPrices::decode_async(&mut recv).await?;
            let token = AccountToken::decode_async(&mut recv).await?;
            let length = u64::decode_async(&mut recv).await? as usize;
            if length != SECTOR_SIZE {
                return Err(format!("sector of {length} bytes").into());
            }
            let mut data = vec![0u8; length];
            recv.read_exact(&mut data).await?;
            check_token(state, &spec, &token).map(|()| {
                if spec.discard_sectors {
                    return encode(&sector_root(&data));
                }
                let sector = Sector::new(data.into());
                let root = sector.root();
                state.sectors.lock().unwrap().insert(root, Arc::new(sector));
                encode(&root)
            })
        }
        "ReadSector" => {
            let _prices = HostPrices::decode_async(&mut recv).await?;
            let token = AccountToken::decode_async(&mut recv).await?;
            let root = Hash256::decode_async(&mut recv).await?;
            let offset = u64::decode_async(&mut recv).await? as usize;
            let length = u64::decode_async(&mut recv).await? as usize;
            tokio::time::sleep(spec.read_delay).await;
            check_token(state, &spec, &token).and_then(|()| {
                if offset > SECTOR_SIZE || length > SECTOR_SIZE - offset {
                    return Err(rpc_error("range out of bounds"));
                }
                let sector = state.sectors.lock().unwrap().get(&root).cloned();
                let (proof, segments) = sector
                    .ok_or_else(|| rpc_error("sector not found"))?
                    .read(offset, length);
                let mut body = encode(&proof);
                segments.encode(&mut body).unwrap();
                Ok(body)
            })
        }
        _ => return Err(format!("unknown RPC {rpc}").into()),
    };
    let mut response = Vec::new();
    match result {
        Ok(body) => {
            false.encode(&mut response)?;
            response.extend(body);
        }
        Err(e) => {
            true.encode(&mut response)?;
            e.encode(&mut response)?;
        }
    }
    // Coreutils 0.25.1 and later send STOP_SENDING once the response is queued, so over a real
    // network it can beat a large response to the browser. Sending it first gives that order here.
    recv.stop(0u32.into());
    send.write_all(&response).await?;
    send.finish().await?;
    Ok(())
}

fn encode(value: &impl SiaEncodable) -> Vec<u8> {
    let mut buf = Vec::new();
    value.encode(&mut buf).unwrap();
    buf
}

fn check_token(state: &State, spec: &HostSpec, token: &AccountToken) -> Result<(), RPCError> {
    if token.valid_until < Utc::now() + spec.clock_ahead {
        state
            .counters
            .expired_tokens
            .fetch_add(1, Ordering::Relaxed);
        return Err(rpc_error("account token expired"));
    }
    Ok(())
}

fn rpc_error(description: &str) -> RPCError {
    RPCError {
        code: 0,
        description: description.into(),
    }
}

/// Settings with zero prices, signed by the host and valid for an hour.
fn settings(key: &PrivateKey) -> HostSettings {
    let mut prices = HostPrices {
        contract_price: Currency::new(0),
        collateral: Currency::new(0),
        storage_price: Currency::new(0),
        ingress_price: Currency::new(0),
        egress_price: Currency::new(0),
        free_sector_price: Currency::new(0),
        tip_height: 1,
        valid_until: Utc::now() + chrono::Duration::hours(1),
        signature: Default::default(),
    };
    prices.signature = key.sign(prices.sig_hash().as_ref());
    HostSettings {
        protocol_version: [4, 0, 0],
        release: "browser_harness".into(),
        wallet_address: Address::default(),
        accepting_contracts: true,
        max_collateral: Currency::new(0),
        max_contract_duration: 0,
        remaining_storage: 1 << 20,
        total_storage: 1 << 20,
        prices,
    }
}
