use std::cell::RefCell;
use std::rc::Rc;

use sia_storage::{Object, SDK, UploadOptions};
use tokio::io::{AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf};
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

use crate::helpers::{run_local, to_js_err};
use crate::object::PinnedObject;
use crate::sdk::OnShardProgressCallback;

type UploadResult = Rc<RefCell<Option<Result<Object, String>>>>;

/// A streaming upload handle. Push data incrementally with `pushChunk()`,
/// then call `finish()` to complete the upload and get the `PinnedObject`.
///
/// This avoids loading the entire file into WASM linear memory at once.
/// The SDK reads from an internal pipe as JS pushes chunks in.
///
/// An optional progress callback can be provided via `setOnProgress()`
/// before the first `pushChunk()` call. It receives `(shardsUploaded)`
/// each time a shard finishes uploading.
#[wasm_bindgen]
pub struct Upload {
    writer: RefCell<Option<WriteHalf<SimplexStream>>>,
    reader: RefCell<Option<ReadHalf<SimplexStream>>>,
    pub(crate) sdk: Rc<SDK>,
    pub(crate) options: UploadOptions,
    on_progress: RefCell<Option<js_sys::Function>>,
    result: UploadResult,
    upload_promise: RefCell<Option<JsFuture>>,
}

impl Upload {
    pub(crate) fn new(
        writer: WriteHalf<SimplexStream>,
        reader: ReadHalf<SimplexStream>,
        sdk: Rc<SDK>,
        options: UploadOptions,
    ) -> Self {
        Self {
            writer: RefCell::new(Some(writer)),
            reader: RefCell::new(Some(reader)),
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

        let (tx, mut rx) = mpsc::unbounded_channel();
        let opts = UploadOptions {
            data_shards: self.options.data_shards,
            parity_shards: self.options.parity_shards,
            max_inflight: self.options.max_inflight,
            shard_uploaded: Some(tx),
        };

        let promise = future_to_promise(async move {
            match run_local(async {
                if let Some(cb) = on_progress {
                    tokio::task::spawn_local(async move {
                        let mut count: u32 = 0;
                        while rx.recv().await.is_some() {
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
    /// data accumulates for a slab.
    #[wasm_bindgen(js_name = "pushChunk")]
    pub async fn push_chunk(&self, data: Vec<u8>) -> Result<(), JsValue> {
        if self.upload_promise.borrow().is_none() {
            self.start_upload()?;
        }

        let mut writer_opt = self.writer.borrow_mut();
        let writer = writer_opt
            .as_mut()
            .ok_or_else(|| JsValue::from_str("upload already finished"))?;
        writer.write_all(&data).await.map_err(to_js_err)
    }

    /// Finish the upload. Closes the write end of the pipe so the SDK
    /// sees EOF, then awaits the upload result.
    /// Returns the PinnedObject handle.
    pub async fn finish(self) -> Result<PinnedObject, JsValue> {
        if self.upload_promise.borrow().is_none() {
            self.start_upload()?;
        }

        // Drop the writer to signal EOF to the reader.
        self.writer.borrow_mut().take();

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
