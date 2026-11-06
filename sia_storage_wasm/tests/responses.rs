#![cfg(target_arch = "wasm32")]

mod common;
#[path = "webtransport/fixtures.rs"]
mod fixtures;

use common::*;
use fixtures::{Harness, HostSpec};
use sia_storage::{AppKey, Object};
use wasm_bindgen_test::wasm_bindgen_test;

/// Hosts on coreutils 0.25.1 and later stop reading a stream when an RPC
/// ends. While the SDK's side of the stream was still open, Firefox
/// discarded the rest of the host's response, so uploads ran out of hosts
/// and downloads failed with too few shards.
#[wasm_bindgen_test]
async fn test_keeps_responses_when_hosts_stop_reading() {
    sia_storage_wasm::init();
    let harness = Harness::default();
    let hosts = harness.reset(&vec![HostSpec::default(); 30]).await;
    let app_key = AppKey::import(rand::random());
    let sdk = sdk(&hosts, &app_key, &[]).await;
    let (object, data) = upload(&sdk, Object::default(), 4 * MIB).await;
    let read = read_range(&sdk, &object, 0, data.len()).await;
    assert_eq!(read.data, data);
}
