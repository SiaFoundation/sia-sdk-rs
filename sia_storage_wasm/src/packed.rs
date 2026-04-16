use std::cell::Cell;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use sia_storage::PackedUpload as CorePackedUpload;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;

/// A packed upload handle for efficiently uploading multiple objects
/// together. Objects are packed into shared slabs to avoid wasting storage.
///
/// ```js
/// const packed = sdk.uploadPacked();
/// await packed.add(file1.stream());
/// await packed.add(file2.stream());
/// const objects = await packed.finalize();
/// for (const obj of objects) await sdk.pinObject(obj);
/// ```
#[wasm_bindgen]
pub struct PackedUpload {
    inner: Arc<Mutex<Option<CorePackedUpload>>>,
    cancelled: Arc<Notify>,
    slab_size: f64,
    length: Cell<f64>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        let slab_size = inner.slab_size() as f64;
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
            cancelled: Arc::new(Notify::new()),
            slab_size,
            length: Cell::new(0.0),
        }
    }
}

#[wasm_bindgen]
impl PackedUpload {
    /// Bytes remaining until the current slab is full. Adding objects that
    /// fit within this size avoids starting a new slab and minimizes padding.
    pub fn remaining(&self) -> f64 {
        let length = self.length.get();
        if length == 0.0 {
            self.slab_size
        } else {
            (self.slab_size - (length % self.slab_size)) % self.slab_size
        }
    }

    /// Total bytes added so far across all objects.
    pub fn length(&self) -> f64 {
        self.length.get()
    }

    /// Optimal size of each slab in bytes.
    #[wasm_bindgen(js_name = "slabSize")]
    pub fn slab_size(&self) -> f64 {
        self.slab_size
    }

    /// Adds an object to the packed upload. Returns the number of bytes written.
    ///
    /// ```js
    /// const packed = sdk.uploadPacked();
    /// await packed.add(file.stream());
    /// await packed.add(blob.stream());
    /// ```
    pub async fn add(&self, stream: web_sys::ReadableStream) -> Result<f64, JsError> {
        let reader = wasm_streams::ReadableStream::from_raw(stream)
            .into_async_read()
            .compat();
        let inner = self.inner.clone();
        let cancelled = self.cancelled.clone();
        let (size, length) = crate::run_local(async move {
            let mut guard = tokio::select! {
                _ = cancelled.notified() => {
                    return Err(JsError::new("upload cancelled"));
                }
                guard = inner.lock() => guard,
            };
            let packed = guard
                .as_mut()
                .ok_or_else(|| JsError::new("upload already finalized"))?;
            let size = tokio::select! {
                _ = cancelled.notified() => {
                    guard.take();
                    return Err(JsError::new("upload cancelled"));
                }
                result = packed.add(reader) => result.map_err(to_js_err)?,
            };
            let length = packed.length() as f64;
            Ok((size as f64, length))
        })
        .await?;
        self.length.set(length);
        Ok(size)
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(self) -> Result<Vec<PinnedObject>, JsError> {
        let inner = self.inner.clone();
        let objects = crate::run_local(async move {
            let packed = inner
                .lock()
                .await
                .take()
                .ok_or_else(|| JsError::new("upload already finalized"))?;
            packed.finalize().await.map_err(to_js_err)
        })
        .await?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Cancels the packed upload. Immediately interrupts any in-flight `add`.
    pub fn cancel(&self) {
        self.cancelled.notify_waiters();
    }
}
