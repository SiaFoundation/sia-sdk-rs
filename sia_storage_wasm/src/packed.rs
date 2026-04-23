use std::cell::Cell;
use std::rc::Rc;
use tokio::sync::Mutex;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use sia_storage::PackedUpload as CorePackedUpload;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;
use crate::stream_reader::js_stream_reader;

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
    inner: Rc<Mutex<Option<CorePackedUpload>>>,
    cancel: CancellationToken,
    optimal_data_size: f64,
    length: Cell<f64>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        let optimal_data_size = inner.optimal_data_size() as f64;
        Self {
            inner: Rc::new(Mutex::new(Some(inner))),
            cancel: CancellationToken::new(),
            optimal_data_size,
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
            self.optimal_data_size
        } else {
            (self.optimal_data_size - (length % self.optimal_data_size)) % self.optimal_data_size
        }
    }

    /// Total bytes added so far across all objects.
    pub fn length(&self) -> f64 {
        self.length.get()
    }

    /// Number of slabs in the upload.
    pub fn slabs(&self) -> f64 {
        let length = self.length.get();
        if length == 0.0 {
            0.0
        } else {
            (length / self.optimal_data_size).ceil()
        }
    }

    /// Optimal size of each slab in bytes.
    #[wasm_bindgen(js_name = "optimalDataSize")]
    pub fn optimal_data_size(&self) -> f64 {
        self.optimal_data_size
    }

    /// Adds an object to the packed upload. Returns the number of bytes written.
    ///
    /// ```js
    /// const packed = sdk.uploadPacked();
    /// await packed.add(file.stream());
    /// await packed.add(blob.stream());
    /// ```
    pub async fn add(&self, stream: web_sys::ReadableStream) -> Result<f64, JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let reader = js_stream_reader(stream).compat();
        let inner = self.inner.clone();
        let cancel = self.cancel.clone();
        let result: Result<u64, JsError> = tokio::select! {
            _ = cancel.cancelled() => Err(JsError::new("upload closed")),
            r = async {
                let mut guard = inner.lock().await;
                // Take ownership so cancel's drop-cascade can abort in-flight
                // slab uploads (they're held as AbortOnDropHandles inside pu).
                let mut pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
                let res = pu.add(reader).await.map_err(to_js_err);
                // Mirror pu.length() rather than accumulating the add's
                // returned size, so partial bytes from an errored add (now
                // kept in pu.length()) stay accounted for.
                let total = pu.length() as f64;
                *guard = Some(pu);
                self.length.set(total);
                res
            } => r,
        };
        Ok(result? as f64)
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(self) -> Result<Vec<PinnedObject>, JsError> {
        if self.cancel.is_cancelled() {
            return Err(JsError::new("upload closed"));
        }
        let inner = self.inner.clone();
        let cancel = self.cancel.clone();
        let result: Result<Vec<sia_storage::Object>, JsError> = tokio::select! {
            _ = cancel.cancelled() => Err(JsError::new("upload closed")),
            r = async {
                let mut guard = inner.lock().await;
                let pu = guard.take().ok_or_else(|| JsError::new("upload closed"))?;
                pu.finalize().await.map_err(to_js_err)
            } => r,
        };
        Ok(result?.into_iter().map(PinnedObject).collect())
    }

    /// Cancels the packed upload. Immediately interrupts any in-flight `add`
    /// and aborts all pending slab uploads.
    pub fn cancel(&self) {
        self.cancel.cancel();
        // If no add/finalize is holding the lock, drop pu here to abort any
        // background slab uploads. If one is holding it, its select! will
        // drop pu when it observes the cancel token.
        if let Ok(mut guard) = self.inner.try_lock() {
            guard.take();
        }
    }
}
