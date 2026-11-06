#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Handshake, Harness, HostSpec};
use sia_storage::{AppKey, Object, UploadOptions};
use std::io::Cursor;
use wasm_bindgen_test::wasm_bindgen_test;
use web_time::Instant;

/// A cold browser upload to a host list where some hosts never answered a
/// handshake stalled for minutes. Uploads ranked hosts they had never used
/// first, so every slab dialed new hosts, and each that never answered added
/// to Chrome's delay on the next handshake.
#[wasm_bindgen_test]
async fn test_cold_upload_keeps_to_hosts_it_reached() {
    sia_storage_wasm::init();
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
    let harness = Harness::default();
    let hosts = harness.reset(&specs).await;
    let app_key = AppKey::import(rand::random());
    // Finish the first slab before selecting hosts for later slabs, so
    // reuse is measured after the SDK has learned which hosts work.
    let options = UploadOptions {
        max_buffered_slabs: Some(1),
        ..Default::default()
    };
    let shards = (options.data_shards + options.parity_shards) as usize;
    let size = options.optimal_data_size() * 6;
    let start = Instant::now();
    let mut data = vec![0; size];
    rand::fill(&mut data[..]);
    let sdk = sdk(&hosts, &app_key, &[]).await;
    sdk.upload(Object::default(), Cursor::new(data), options)
        .await
        .expect("upload");
    let throughput = size as f64 / start.elapsed().as_secs_f64() / MIB as f64;
    let connected = harness
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
