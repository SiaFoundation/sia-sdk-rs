#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Harness, HostSpec};
use sia_storage::{AppKey, Object};
use wasm_bindgen_test::wasm_bindgen_test;

/// #487: concurrent reads from a host each fetched its prices, so a first
/// play asked each host for its prices 11 times on average.
#[wasm_bindgen_test]
async fn test_concurrent_reads_share_price_fetches() {
    sia_storage_wasm::init();
    let harness = Harness::default();
    let hosts = harness.reset(&vec![HostSpec::default(); 30]).await;
    let app_key = AppKey::import(rand::random());
    let (object, _) = upload(
        &sdk(&hosts, &app_key, &[]).await,
        Object::default(),
        8 * MIB,
    )
    .await;
    let before = harness.stats().await;

    let sdk = sdk(&hosts, &app_key, &[]).await;
    tokio::join!(
        read_range(&sdk, &object, 0, MIB),
        read_range(&sdk, &object, 2 * MIB, MIB),
        read_range(&sdk, &object, 4 * MIB, MIB),
        read_range(&sdk, &object, 6 * MIB, MIB),
    );
    let fetches: Vec<u64> = harness
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
