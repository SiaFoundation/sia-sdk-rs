#![allow(dead_code)]

use std::io::Cursor;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use sia_core::types::v2::NetAddress;
use sia_storage::mock::MockIndexer;
use sia_storage::{AppKey, DownloadOptions, Host, Object, Protocol, Sdk, UploadOptions};
use tokio::io::AsyncReadExt;
use web_time::Instant;

use crate::fixtures::FakeHost;

pub const MIB: usize = 1 << 20;

/// An SDK with an indexer that lists every fake host except those in `skip`.
pub async fn sdk(hosts: &[FakeHost], app_key: &AppKey, skip: &[usize]) -> Sdk {
    let hosts = hosts
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
    MockIndexer::new(hosts).sdk(app_key.clone()).await.unwrap()
}

/// Uploads `size` random bytes, appending them to `object`, and returns
/// the new object and the bytes.
pub async fn upload(sdk: &Sdk, object: Object, size: usize) -> (Object, Bytes) {
    let mut data = BytesMut::zeroed(size);
    rand::fill(&mut data[..]);
    let data = data.freeze();
    let object = sdk
        .upload(object, Cursor::new(data.clone()), UploadOptions::default())
        .await
        .expect("upload");
    (object, data)
}

pub struct RangeRead {
    pub first_byte: Duration,
    pub data: Bytes,
}

/// Reads `length` bytes at `offset`, the way a video element's range request
/// reaches the SDK.
pub async fn read_range(sdk: &Sdk, object: &Object, offset: usize, length: usize) -> RangeRead {
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

pub async fn sleep(duration: Duration) {
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
