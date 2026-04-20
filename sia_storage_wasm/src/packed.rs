use std::cell::Cell;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};
use wasm_streams::readable::IntoAsyncRead;

use sia_storage::PackedUpload as CorePackedUpload;
use wasm_bindgen::prelude::*;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;

type PackedReader = Compat<IntoAsyncRead<'static>>;

enum PackedUploadAction {
    Add(
        PackedReader,
        oneshot::Sender<Result<u64, sia_storage::UploadError>>,
    ),
    Finalize(oneshot::Sender<Result<Vec<sia_storage::Object>, sia_storage::UploadError>>),
}

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
    upload_task: tokio::task::JoinHandle<()>,
    tx: mpsc::Sender<PackedUploadAction>,
    slab_size: f64,
    length: Cell<f64>,
    closed: Cell<bool>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        let slab_size = inner.slab_size() as f64;
        let (action_tx, mut action_rx) = mpsc::channel(10);
        let upload_task = tokio::task::spawn_local(async move {
            let mut packed_upload = inner;
            while let Some(action) = action_rx.recv().await {
                match action {
                    PackedUploadAction::Add(reader, add_tx) => {
                        let res = packed_upload.add(reader).await;
                        let _ = add_tx.send(res);
                    }
                    PackedUploadAction::Finalize(finalize_tx) => {
                        let result = packed_upload.finalize().await;
                        let _ = finalize_tx.send(result);
                        return;
                    }
                }
            }
        });
        Self {
            upload_task,
            tx: action_tx,
            slab_size,
            length: Cell::new(0.0),
            closed: Cell::new(false),
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

    /// Number of slabs in the upload.
    pub fn slabs(&self) -> f64 {
        let length = self.length.get();
        if length == 0.0 {
            0.0
        } else {
            (length / self.slab_size).ceil()
        }
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
        if self.closed.get() {
            return Err(JsError::new("upload already finalized"));
        }
        let reader = wasm_streams::ReadableStream::from_raw(stream)
            .into_async_read()
            .compat();
        let (add_tx, add_rx) = oneshot::channel();
        self.tx
            .send(PackedUploadAction::Add(reader, add_tx))
            .await
            .map_err(|_| JsError::new("upload closed"))?;
        let size = add_rx
            .await
            .map_err(|_| JsError::new("upload closed"))?
            .map_err(to_js_err)?;
        let size = size as f64;
        self.length.set(self.length.get() + size);
        Ok(size)
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(self) -> Result<Vec<PinnedObject>, JsError> {
        if self.closed.replace(true) {
            return Err(JsError::new("upload already finalized"));
        }
        let (finalize_tx, finalize_rx) = oneshot::channel();
        self.tx
            .send(PackedUploadAction::Finalize(finalize_tx))
            .await
            .map_err(|_| JsError::new("upload closed"))?;
        let objects = finalize_rx
            .await
            .map_err(|_| JsError::new("upload closed"))?
            .map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Cancels the packed upload. Immediately interrupts any in-flight `add`
    /// and aborts all pending slab uploads.
    pub fn cancel(&self) {
        if self.closed.replace(true) {
            return;
        }
        // Aborting the task drops the owned PackedUpload, which aborts every
        // pending slab task via AbortOnDropHandle inside the core upload.
        self.upload_task.abort();
    }
}
