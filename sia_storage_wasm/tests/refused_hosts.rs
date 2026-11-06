#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Handshake, Harness, HostSpec};
use sia_storage::{AppKey, Object, UploadOptions};
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

/// #502: a host that refused a handshake was dialed again by every read,
/// and each refusal added to Chrome's delay, so seeking or reaching the next
/// slab of a video stalled for up to a minute.
#[wasm_bindgen_test]
async fn test_refused_hosts_are_not_redialed() {
    sia_storage_wasm::init();
    let harness = Harness::default();
    let hosts = harness.reset(&vec![HostSpec::default(); 60]).await;
    let app_key = AppKey::import(rand::random());
    let first_slab_hosts: Vec<usize> = (0..30).collect();
    let second_slab_hosts: Vec<usize> = (30..60).collect();
    // A full first slab, so the second upload starts a new slab instead of
    // rewriting this one's tail.
    let slab_size = UploadOptions::default().optimal_data_size();
    let (object, first) = upload(
        &sdk(&hosts, &app_key, &second_slab_hosts).await,
        Object::default(),
        slab_size,
    )
    .await;
    let (object, second) = upload(
        &sdk(&hosts, &app_key, &first_slab_hosts).await,
        object,
        4 * MIB,
    )
    .await;
    let data = [first, second].concat();
    let refusing = HostSpec {
        handshake: Handshake::Refuse,
        ..Default::default()
    };
    for i in 0..3 {
        harness.set(i, &refusing).await;
    }
    let before = harness.stats().await;

    let sdk = sdk(&hosts, &app_key, &[]).await;
    for seek in 0..6 {
        let offset = seek * 512 * 1024;
        let read = read_range(&sdk, &object, offset, 64 * 1024).await;
        assert_eq!(read.data, data[offset..][..64 * 1024]);
    }
    let read = read_range(&sdk, &object, slab_size, 64 * 1024).await;
    assert_eq!(read.data, data[slab_size..][..64 * 1024]);

    let refusals: Vec<u64> = harness.stats().await[..3]
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
