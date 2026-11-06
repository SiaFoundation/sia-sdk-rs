#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Harness, HostSpec};
use sia_storage::{AppKey, Object};
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

/// #503: a read took its account token before dialing the host, and in
/// Chrome a dial can wait minutes, so the token expired before the host saw
/// it. Here every dial takes 12 seconds and the hosts' clocks run 4 minutes
/// 50 seconds ahead, so a token that waits more than 10 seconds of its five
/// minutes is expired.
#[wasm_bindgen_test]
async fn test_reads_take_their_token_after_dialing() {
    sia_storage_wasm::init();
    let harness = Harness::default();
    let hosts = harness.reset(&vec![HostSpec::default(); 30]).await;
    let app_key = AppKey::import(rand::random());
    let (object, data) = upload(
        &sdk(&hosts, &app_key, &[]).await,
        Object::default(),
        4 * MIB,
    )
    .await;
    for i in 0..hosts.len() {
        harness
            .set(
                i,
                &HostSpec {
                    handshake_delay: Duration::from_secs(12),
                    clock_ahead: Duration::from_secs(290),
                    ..Default::default()
                },
            )
            .await;
    }

    let read = read_range(&sdk(&hosts, &app_key, &[]).await, &object, 0, MIB).await;
    assert_eq!(read.data, data[..MIB]);
    let expired: u64 = harness.stats().await.iter().map(|s| s.expired_tokens).sum();
    assert_eq!(expired, 0, "hosts rejected expired tokens");
}
