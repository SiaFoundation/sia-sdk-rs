#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Harness, HostSpec};
use sia_storage::{AppKey, Object};
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

/// #510: a stream whose open was abandoned, because its read was cancelled,
/// stayed open once it did open. A video player cancels reads whenever the
/// viewer seeks, so streams piled up on each host until it opened no more.
#[wasm_bindgen_test]
async fn test_cancelled_reads_do_not_leak_streams() {
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
                    read_delay: Duration::from_millis(300),
                    ..Default::default()
                },
            )
            .await;
    }

    let sdk = sdk(&hosts, &app_key, &[]).await;
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
        open = harness.stats().await.iter().map(|s| s.open_streams).sum();
        if open == 0 {
            break;
        }
    }
    let read = read_range(&sdk, &object, MIB, 256 * 1024).await;
    assert_eq!(read.data, data[MIB..][..256 * 1024]);
    assert_eq!(open, 0, "streams left open after seeking");
}
