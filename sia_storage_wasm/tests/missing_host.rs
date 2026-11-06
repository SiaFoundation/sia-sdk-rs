#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Harness, HostSpec};
use sia_storage::{AppKey, Object};
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

/// #506: a slab with a sector on a host missing from the host list panicked
/// with an index out of bounds, which stopped every stream on the page. It
/// needs a shard after the missing one to arrive first, as it did in Safari,
/// which opens a video with several overlapping range requests.
#[wasm_bindgen_test]
async fn test_host_missing_from_host_list_does_not_panic() {
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
    let sectors = &object.slabs()[0].sectors;
    let host_index = |key| hosts.iter().position(|h| h.public_key == key).unwrap();
    let missing = host_index(sectors[0].host_key);
    let fastest = host_index(sectors[sectors.len() - 1].host_key);
    let slow = HostSpec {
        read_delay: Duration::from_millis(300),
        ..Default::default()
    };
    for i in (0..hosts.len()).filter(|&i| i != fastest) {
        harness.set(i, &slow).await;
    }

    let sdk = sdk(&hosts, &app_key, &[missing]).await;
    let (a, b, c) = tokio::join!(
        read_range(&sdk, &object, 0, 2 * MIB),
        read_range(&sdk, &object, MIB, 2 * MIB),
        read_range(&sdk, &object, 0, 4 * MIB),
    );
    for (offset, read) in [(0, a), (MIB, b), (0, c)] {
        assert_eq!(read.data, data[offset..][..read.data.len()]);
    }
}
