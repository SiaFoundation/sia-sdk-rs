use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use napi::bindgen_prelude::*;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

const DEFAULT_CAPACITY: usize = 128 * 1024; // 128 KiB

type MapChunkFn =
    fn(std::result::Result<Buffer, Error>) -> std::result::Result<Bytes, std::io::Error>;
pub(crate) type NapiStreamReader =
    tokio_util::io::StreamReader<tokio_stream::adapters::Map<Reader<Buffer>, MapChunkFn>, Bytes>;

/// A Send-safe wrapper around a JS `ReadableStream` that converts it into an
/// `AsyncRead` during napi parameter extraction. This allows it to be used
/// directly in `#[napi] async fn` signatures without manual `execute_tokio_future`.
pub struct SendableReader(pub(crate) NapiStreamReader);

impl FromNapiValue for SendableReader {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        value: napi::sys::napi_value,
    ) -> Result<Self> {
        fn map_chunk(
            r: std::result::Result<Buffer, Error>,
        ) -> std::result::Result<Bytes, std::io::Error> {
            r.map(|buf| Bytes::from(buf.to_vec()))
                .map_err(|e| std::io::Error::other(e.reason.clone()))
        }
        let stream = unsafe { ReadableStream::<Buffer>::from_napi_value(env, value)? };
        let reader = stream.read()?;
        let mapped = reader.map(map_chunk as MapChunkFn);
        Ok(Self(tokio_util::io::StreamReader::new(mapped)))
    }
}

/// A `Stream<Item = Result<Vec<u8>>>` backed by a spawned tokio task that
/// reads from an `AsyncRead`. The reader runs entirely within the tokio
/// runtime, avoiding issues with napi callbacks lacking a runtime context.
/// Each chunk is a freshly allocated `Vec<u8>` transferred via channel —
/// no intermediate copies.
pub(crate) struct AsyncReadStream {
    rx: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    _task: JoinHandle<()>,
}

impl AsyncReadStream {
    pub fn new<R: tokio::io::AsyncRead + Unpin + Send + 'static>(reader: R) -> Self {
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let mut reader = reader;
            loop {
                let mut buf = vec![0u8; DEFAULT_CAPACITY];
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.truncate(n);
                        if tx.send(Ok(buf)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });
        Self { rx, _task: task }
    }
}

impl Stream for AsyncReadStream {
    type Item = std::io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}
