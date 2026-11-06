//! Tests that run the SDK in headless Chrome and Firefox against fake hosts
//! on localhost, through its public API and a [`MockIndexer`] that lists the
//! fake hosts, so every RPC goes through the browser's own WebTransport and
//! meets its real limits, such as Chrome's delay on new handshakes after
//! failed ones. Each test reproduces a problem the browser SDK once had. A
//! test inside a module named after a browser, such as `chrome`, runs only in
//! that browser. They need the hosts from `testutil/browser_harness`, which
//! also runs them, each in a fresh browser:
//!
//! ```sh
//! cargo run -p browser_harness [-- <test name filter>...]
//! ```

#![cfg(target_arch = "wasm32")]

use std::io::Cursor;
use std::sync::{Once, OnceLock};
use std::time::Duration;

use browser_harness::{FakeHost, Handshake, Harness, HostSpec};
use bytes::{Bytes, BytesMut};
use sia_core::types::v2::NetAddress;
use sia_storage::mock::MockIndexer;
use sia_storage::{AppKey, DownloadOptions, Host, Object, Protocol, Sdk, UploadOptions};
use tokio::io::AsyncReadExt;
use wasm_bindgen_test::wasm_bindgen_test;
use web_time::Instant;

const MIB: usize = 1 << 20;

struct World {
    harness: Harness,
    hosts: Vec<FakeHost>,
    app_key: AppKey,
}

impl World {
    async fn new(specs: &[HostSpec]) -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            log::set_logger(&Console).unwrap();
            log::set_max_level(log::LevelFilter::Debug);
            run_tokio_tasks();
        });
        let harness = Harness::default();
        let hosts = harness.reset(specs).await;
        Self {
            harness,
            hosts,
            app_key: AppKey::import(rand::random()),
        }
    }

    /// An SDK as a newly opened page has it, with an indexer that lists every
    /// fake host except those in `skip`.
    async fn sdk(&self, skip: &[usize]) -> Sdk {
        let hosts = self
            .hosts
            .iter()
            .enumerate()
            .filter(|(i, _)| !skip.contains(i))
            .map(|(_, host)| Host {
                public_key: host.public_key,
                addresses: vec![NetAddress {
                    protocol: Protocol::QUIC,
                    address: host.address.to_string(),
                }],
                country_code: "US".into(),
                latitude: 0.0,
                longitude: 0.0,
                good_for_upload: true,
            })
            .collect();
        MockIndexer::new(hosts)
            .sdk(self.app_key.clone())
            .await
            .unwrap()
    }

    /// Uploads `size` random bytes, appending them to `object`, and returns
    /// the new object and the bytes.
    async fn upload(&self, sdk: &Sdk, object: Object, size: usize) -> (Object, Bytes) {
        let mut data = BytesMut::zeroed(size);
        rand::fill(&mut data[..]);
        let data = data.freeze();
        let object = sdk
            .upload(object, Cursor::new(data.clone()), UploadOptions::default())
            .await
            .expect("upload");
        (object, data)
    }

    async fn set_all(&self, spec: &HostSpec) {
        for i in 0..self.hosts.len() {
            self.harness.set(i, spec).await;
        }
    }
}

struct RangeRead {
    first_byte: Duration,
    data: Bytes,
}

/// Reads `length` bytes at `offset`, the way a video element's range request
/// reaches the SDK.
async fn read_range(sdk: &Sdk, object: &Object, offset: usize, length: usize) -> RangeRead {
    let start = Instant::now();
    let mut download = sdk
        .download(
            object,
            DownloadOptions {
                offset: offset as u64,
                length: Some(length as u64),
                ..Default::default()
            },
        )
        .unwrap();
    let mut data = vec![0u8; length];
    let n = download.read(&mut data).await.unwrap();
    let first_byte = start.elapsed();
    download.read_exact(&mut data[n..]).await.unwrap();
    RangeRead {
        first_byte,
        data: data.into(),
    }
}

/// Sets the page up the way the WASM bindings' `init` does. The SDK spawns
/// background tasks with `tokio::task::spawn_local`, which panics outside a
/// tokio `LocalSet`, so one runs for the rest of the page's life.
fn run_tokio_tasks() {
    let runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    ));
    let local_set: &'static _ = Box::leak(Box::new(tokio::task::LocalSet::new()));
    std::mem::forget(runtime.enter());
    std::mem::forget(local_set.enter());
    wasm_bindgen_futures::spawn_local(local_set.run_until(std::future::pending::<()>()));
}

async fn sleep(duration: Duration) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let set_timeout: js_sys::Function =
            js_sys::Reflect::get(&js_sys::global(), &"setTimeout".into())
                .unwrap()
                .into();
        set_timeout
            .call2(
                &wasm_bindgen::JsValue::NULL,
                &resolve,
                &(duration.as_millis() as f64).into(),
            )
            .unwrap();
    });
    wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
}

/// Sends the SDK's debug log to the console, which the test runner prints
/// when a test fails.
struct Console;

static START: OnceLock<Instant> = OnceLock::new();

impl log::Log for Console {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("sia_storage")
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let elapsed = START.get_or_init(Instant::now).elapsed().as_secs_f64();
            wasm_bindgen_test::console_log!("{elapsed:9.3} {} {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

fn accepting(n: usize) -> Vec<HostSpec> {
    vec![HostSpec::default(); n]
}

/// #502: a host that refused a handshake was dialed again by every read,
/// and each refusal added to Chrome's delay, so seeking or reaching the next
/// slab of a video stalled for up to a minute.
#[wasm_bindgen_test]
async fn test_refused_hosts_are_not_redialed() {
    let world = World::new(&accepting(60)).await;
    let first_slab_hosts: Vec<usize> = (0..30).collect();
    let second_slab_hosts: Vec<usize> = (30..60).collect();
    // A full first slab, so the second upload starts a new slab instead of
    // rewriting this one's tail.
    let slab_size = UploadOptions::default().optimal_data_size();
    let (object, first) = world
        .upload(
            &world.sdk(&second_slab_hosts).await,
            Object::default(),
            slab_size,
        )
        .await;
    let (object, second) = world
        .upload(&world.sdk(&first_slab_hosts).await, object, 4 * MIB)
        .await;
    let data = [first, second].concat();
    let refusing = HostSpec {
        handshake: Handshake::Refuse,
        ..Default::default()
    };
    for i in 0..3 {
        world.harness.set(i, &refusing).await;
    }
    let before = world.harness.stats().await;

    let sdk = world.sdk(&[]).await;
    for seek in 0..6 {
        let offset = seek * 512 * 1024;
        let read = read_range(&sdk, &object, offset, 64 * 1024).await;
        assert_eq!(read.data, data[offset..][..64 * 1024]);
    }
    let read = read_range(&sdk, &object, slab_size, 64 * 1024).await;
    assert_eq!(read.data, data[slab_size..][..64 * 1024]);

    let refusals: Vec<u64> = world.harness.stats().await[..3]
        .iter()
        .zip(&before)
        .map(|(after, before)| after.handshakes - before.handshakes)
        .collect();
    assert!(
        read.first_byte < Duration::from_secs(10),
        "the second slab's first byte took {:?}, refused handshakes per host {refusals:?}",
        read.first_byte
    );
    assert!(
        refusals.iter().all(|&n| n <= 1),
        "refusing hosts were dialed {refusals:?} times"
    );
}

/// #506: a slab with a sector on a host missing from the host list panicked
/// with an index out of bounds, which stopped every stream on the page. It
/// needs a shard after the missing one to arrive first, as it did in Safari,
/// which opens a video with several overlapping range requests.
#[wasm_bindgen_test]
async fn test_host_missing_from_host_list_does_not_panic() {
    let world = World::new(&accepting(30)).await;
    let (object, data) = world
        .upload(&world.sdk(&[]).await, Object::default(), 4 * MIB)
        .await;
    let sectors = &object.slabs()[0].sectors;
    let host_index = |key| {
        world
            .hosts
            .iter()
            .position(|h| h.public_key == key)
            .unwrap()
    };
    let missing = host_index(sectors[0].host_key);
    let fastest = host_index(sectors[sectors.len() - 1].host_key);
    let slow = HostSpec {
        read_delay: Duration::from_millis(300),
        ..Default::default()
    };
    for i in (0..world.hosts.len()).filter(|&i| i != fastest) {
        world.harness.set(i, &slow).await;
    }

    let sdk = world.sdk(&[missing]).await;
    let (a, b, c) = tokio::join!(
        read_range(&sdk, &object, 0, 2 * MIB),
        read_range(&sdk, &object, MIB, 2 * MIB),
        read_range(&sdk, &object, 0, 4 * MIB),
    );
    for (offset, read) in [(0, a), (MIB, b), (0, c)] {
        assert_eq!(read.data, data[offset..][..read.data.len()]);
    }
}

/// #510: a stream whose open was abandoned, because its read was cancelled,
/// stayed open once it did open. A video player cancels reads whenever the
/// viewer seeks, so streams piled up on each host until it opened no more.
#[wasm_bindgen_test]
async fn test_cancelled_reads_do_not_leak_streams() {
    let world = World::new(&accepting(30)).await;
    let (object, data) = world
        .upload(&world.sdk(&[]).await, Object::default(), 4 * MIB)
        .await;
    world
        .set_all(&HostSpec {
            read_delay: Duration::from_millis(300),
            ..Default::default()
        })
        .await;

    let sdk = world.sdk(&[]).await;
    for seek in 0..40 {
        let offset = seek * 97 * 1024 % (3 * MIB);
        tokio::select! {
            _ = read_range(&sdk, &object, offset, 256 * 1024) => {}
            _ = sleep(Duration::from_millis(5 + seek as u64 % 7 * 20)) => {}
        }
    }
    // Reads still in flight finish within a second. A leaked stream stays.
    let mut open = 0;
    for _ in 0..20 {
        sleep(Duration::from_millis(500)).await;
        open = world
            .harness
            .stats()
            .await
            .iter()
            .map(|s| s.open_streams)
            .sum();
        if open == 0 {
            break;
        }
    }
    let read = read_range(&sdk, &object, MIB, 256 * 1024).await;
    assert_eq!(read.data, data[MIB..][..256 * 1024]);
    assert_eq!(open, 0, "streams left open after seeking");
}

/// #487: concurrent reads from a host each fetched its prices, so a first
/// play asked each host for its prices 11 times on average.
#[wasm_bindgen_test]
async fn test_concurrent_reads_share_price_fetches() {
    let world = World::new(&accepting(30)).await;
    let (object, _) = world
        .upload(&world.sdk(&[]).await, Object::default(), 8 * MIB)
        .await;
    let before = world.harness.stats().await;

    let sdk = world.sdk(&[]).await;
    tokio::join!(
        read_range(&sdk, &object, 0, MIB),
        read_range(&sdk, &object, 2 * MIB, MIB),
        read_range(&sdk, &object, 4 * MIB, MIB),
        read_range(&sdk, &object, 6 * MIB, MIB),
    );
    let fetches: Vec<u64> = world
        .harness
        .stats()
        .await
        .iter()
        .zip(&before)
        .map(|(after, before)| after.settings - before.settings)
        .collect();
    // A fetch is dropped when every read waiting on it is cancelled, as the
    // losers of a race are, and the next read fetches again.
    assert!(
        fetches.iter().all(|&n| n <= 2),
        "price fetches per host: {fetches:?}"
    );
}

/// #503: a read took its account token before dialing the host, and in
/// Chrome a dial can wait minutes, so the token expired before the host saw
/// it. Here every dial takes 12 seconds and the hosts' clocks run 4 minutes
/// 50 seconds ahead, so a token that waits more than 10 seconds of its five
/// minutes is expired.
#[wasm_bindgen_test]
async fn test_reads_take_their_token_after_dialing() {
    let world = World::new(&accepting(30)).await;
    let (object, data) = world
        .upload(&world.sdk(&[]).await, Object::default(), 4 * MIB)
        .await;
    world
        .set_all(&HostSpec {
            handshake_delay: Duration::from_secs(12),
            clock_ahead: Duration::from_secs(290),
            ..Default::default()
        })
        .await;

    let read = read_range(&world.sdk(&[]).await, &object, 0, MIB).await;
    assert_eq!(read.data, data[..MIB]);
    let expired: u64 = world
        .harness
        .stats()
        .await
        .iter()
        .map(|s| s.expired_tokens)
        .sum();
    assert_eq!(expired, 0, "hosts rejected expired tokens");
}

/// Tests of how Chrome treats WebTransport, which Firefox does not share.
mod chrome {
    use wasm_bindgen_futures::JsFuture;

    use super::*;

    /// Chrome counts a failed handshake for five minutes. While it counts `n`
    /// failed or in-flight handshakes, it holds each new one back by
    /// `10 ms * 2^(n - 1)`, or by a minute once `n` passes 13, times a random
    /// 0.5 to 1.5. Other tests depend on meeting that delay, so this checks the
    /// fake hosts still trigger it.
    #[wasm_bindgen_test]
    async fn test_chrome_delays_handshakes_after_failed_ones() {
        let mut specs = accepting(1);
        specs.extend(vec![
            HostSpec {
                handshake: Handshake::Refuse,
                ..Default::default()
            };
            11
        ]);
        let world = World::new(&specs).await;
        let open = |host: &FakeHost| {
            web_sys::WebTransport::new(&format!("https://{}/sia/rhp/v4", host.address)).unwrap()
        };
        for host in &world.hosts[1..] {
            assert!(JsFuture::from(open(host).ready()).await.is_err());
        }
        let start = Instant::now();
        let session = open(&world.hosts[0]);
        JsFuture::from(session.ready())
            .await
            .expect("healthy host connects");
        let waited = start.elapsed();
        session.close();
        assert!(
            waited > Duration::from_secs(2),
            "a handshake after 11 failed ones took only {waited:?}"
        );
    }

    /// A cold browser upload to a host list where some hosts never answered a
    /// handshake stalled for minutes. Uploads ranked hosts they had never used
    /// first, so every slab dialed new hosts, and each that never answered added
    /// to Chrome's delay on the next handshake.
    #[wasm_bindgen_test]
    async fn test_cold_upload_keeps_to_hosts_it_reached() {
        // 13 hosts never answer. An upload that dials most of them gets every
        // later handshake held back by up to a minute and a half. One that keeps
        // to the hosts it reached rarely meets more than 10, which hold each
        // back by at most about 8 seconds.
        let specs: Vec<HostSpec> = (0..100)
            .map(|i| HostSpec {
                handshake: if i % 8 == 0 {
                    Handshake::Ignore
                } else {
                    Handshake::Accept
                },
                discard_sectors: true,
                ..Default::default()
            })
            .collect();
        let world = World::new(&specs).await;
        let options = UploadOptions::default();
        let shards = (options.data_shards + options.parity_shards) as usize;
        let size = options.optimal_data_size() * 6;
        let start = Instant::now();
        world
            .upload(&world.sdk(&[]).await, Object::default(), size)
            .await;
        let throughput = size as f64 / start.elapsed().as_secs_f64() / MIB as f64;
        let connected = world
            .harness
            .stats()
            .await
            .iter()
            .filter(|s| s.sessions > 0)
            .count();
        assert!(
            connected < 2 * shards,
            "connected to {connected} hosts for slabs of {shards} shards"
        );
        assert!(throughput > 3.0, "uploaded at {throughput:.1} MiB/s");
    }
}

/// Tests of how Firefox treats WebTransport, which Chrome does not share.
mod firefox {
    use super::*;

    /// Hosts on coreutils 0.25.1 and later stop reading a stream when they
    /// close it. While the SDK's side of the stream was still open, Firefox
    /// discarded the rest of the host's response, so sector writes failed
    /// and uploads ran out of hosts.
    #[wasm_bindgen_test]
    async fn test_firefox_keeps_responses_when_hosts_stop_reading() {
        let world = World::new(&accepting(30)).await;
        world
            .upload(&world.sdk(&[]).await, Object::default(), 4 * MIB)
            .await;
    }
}
