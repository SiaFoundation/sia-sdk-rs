use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use sia_storage::{Object, SDK, UploadOptions};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

use crate::helpers::run_local;
use crate::object::PinnedObject;
use crate::sdk::OnShardProgressCallback;

type UploadResult = Rc<RefCell<Option<Result<Object, String>>>>;

/// An AsyncRead adapter backed by a channel of owned Bytes chunks.
/// Avoids the extra memcpy that SimplexStream requires — each chunk
/// is moved into the reader via Bytes::from(Vec<u8>) (zero-copy
/// ownership transfer) and then read directly by the SDK.
struct ChannelReader {
    rx: mpsc::UnboundedReceiver<Bytes>,
    current: Bytes,
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain remaining bytes from the current chunk first.
        if !self.current.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.current.len());
            buf.put_slice(&self.current[..n]);
            self.current = self.current.split_off(n);
            return Poll::Ready(Ok(()));
        }

        // Pull the next chunk from the channel.
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                let n = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() {
                    self.current = bytes.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF — sender dropped
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncBufRead for ChannelReader {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.current.is_empty() {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => this.current = bytes,
                Poll::Ready(None) => return Poll::Ready(Ok(&[])),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(&this.current))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().current.advance(amt);
    }
}

/// An upload handle. Push data with `pushChunk()`,
/// then call `finish()` to complete the upload and get the `PinnedObject`.
///
/// This avoids loading the entire file into WASM linear memory at once.
/// The SDK reads from an internal channel as JS pushes chunks in.
/// Each chunk is transferred via zero-copy `Bytes` ownership, eliminating
/// the intermediate buffer copy that a pipe (SimplexStream) would require.
///
/// An optional progress callback can be provided via `setOnProgress()`
/// before the first `pushChunk()` call. It receives `(shardsUploaded)`
/// each time a shard finishes uploading.
#[wasm_bindgen]
pub struct Upload {
    tx: RefCell<Option<mpsc::UnboundedSender<Bytes>>>,
    reader: RefCell<Option<ChannelReader>>,
    pub(crate) sdk: Rc<SDK>,
    pub(crate) options: UploadOptions,
    on_progress: RefCell<Option<js_sys::Function>>,
    result: UploadResult,
    upload_promise: RefCell<Option<JsFuture>>,
}

impl Upload {
    pub(crate) fn new(sdk: Rc<SDK>, options: UploadOptions) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx: RefCell::new(Some(tx)),
            reader: RefCell::new(Some(ChannelReader {
                rx,
                current: Bytes::new(),
            })),
            sdk,
            options,
            on_progress: RefCell::new(None),
            result: Rc::new(RefCell::new(None)),
            upload_promise: RefCell::new(None),
        }
    }

    fn start_upload(&self) -> Result<(), JsValue> {
        let reader = self
            .reader
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload already started"))?;
        let sdk = self.sdk.clone();
        let result = self.result.clone();
        let on_progress = self.on_progress.borrow_mut().take();

        let (shard_tx, mut shard_rx) = mpsc::unbounded_channel();
        let opts = UploadOptions {
            data_shards: self.options.data_shards,
            parity_shards: self.options.parity_shards,
            max_inflight: self.options.max_inflight,
            shard_uploaded: Some(shard_tx),
        };

        let promise = future_to_promise(async move {
            match run_local(async {
                if let Some(cb) = on_progress {
                    tokio::task::spawn_local(async move {
                        let mut count: u32 = 0;
                        while shard_rx.recv().await.is_some() {
                            count += 1;
                            let _ = cb.call1(&JsValue::NULL, &JsValue::from(count));
                        }
                    });
                }
                sdk.upload(reader, opts).await
            })
            .await
            {
                Ok(obj) => {
                    *result.borrow_mut() = Some(Ok(obj));
                    Ok(JsValue::UNDEFINED)
                }
                Err(e) => {
                    let msg = e.to_string();
                    *result.borrow_mut() = Some(Err(msg.clone()));
                    Err(JsValue::from_str(&msg))
                }
            }
        });
        *self.upload_promise.borrow_mut() = Some(JsFuture::from(promise));
        Ok(())
    }
}

#[wasm_bindgen]
impl Upload {
    /// Sets a progress callback. Must be called before the first `pushChunk()`.
    /// The callback receives `(shardsUploaded: number)` each time a shard
    /// finishes uploading.
    #[wasm_bindgen(js_name = "setOnProgress")]
    pub fn set_on_progress(&self, callback: OnShardProgressCallback) {
        let func: js_sys::Function = callback.unchecked_into();
        *self.on_progress.borrow_mut() = Some(func);
    }

    /// Push a chunk of data into the upload stream. The SDK will begin
    /// processing (erasure coding + uploading shards) as soon as enough
    /// data accumulates for a slab (~40 MiB). The chunk data is transferred
    /// to the SDK via zero-copy ownership (no intermediate buffer copy).
    #[wasm_bindgen(js_name = "pushChunk")]
    pub fn push_chunk(&self, data: Vec<u8>) -> Result<(), JsValue> {
        if self.upload_promise.borrow().is_none() {
            self.start_upload()?;
        }

        let tx = self.tx.borrow();
        let tx = tx
            .as_ref()
            .ok_or_else(|| JsValue::from_str("upload already finished"))?;
        tx.send(Bytes::from(data)).map_err(|_| {
            JsValue::from_str("upload channel closed — upload task may have failed")
        })
    }

    /// Finish the upload. Closes the channel so the SDK sees EOF,
    /// then awaits the upload result.
    /// Returns the PinnedObject handle.
    pub async fn finish(self) -> Result<PinnedObject, JsValue> {
        if self.upload_promise.borrow().is_none() {
            self.start_upload()?;
        }

        // Drop the sender to signal EOF to the reader.
        self.tx.borrow_mut().take();

        // Await the upload task completion.
        let promise = self
            .upload_promise
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload not started"))?;
        let _ = promise.await;

        // Take the result stored by the upload task.
        let result = self
            .result
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload produced no result"))?;
        match result {
            Ok(obj) => Ok(PinnedObject(obj)),
            Err(e) => Err(JsValue::from_str(&e)),
        }
    }
}
