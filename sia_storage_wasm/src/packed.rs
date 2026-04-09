use std::cell::RefCell;
use std::io::Cursor;

use sia_storage::PackedUpload as CorePackedUpload;
use wasm_bindgen::prelude::*;

use crate::helpers::{run_local, to_js_err};
use crate::object::PinnedObject;

/// A packed upload handle for efficiently uploading multiple small objects
/// together. Objects smaller than the slab size (~40 MiB) are packed into
/// shared slabs to avoid wasting storage.
///
/// ```js
/// let packed = sdk.uploadPacked();
/// await packed.add(smallFile1);  // returns bytes written
/// await packed.add(smallFile2);
/// let objects = await packed.finalize();  // returns PinnedObject[]
/// for (let obj of objects) await sdk.pinObject(obj);
/// ```
#[wasm_bindgen]
pub struct PackedUpload {
    inner: RefCell<Option<CorePackedUpload>>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        Self {
            inner: RefCell::new(Some(inner)),
        }
    }
}

#[wasm_bindgen]
impl PackedUpload {
    /// Bytes remaining until the current slab is full. Adding objects that
    /// fit within this size avoids starting a new slab and minimizes padding.
    pub fn remaining(&self) -> Result<f64, JsValue> {
        let inner = self.inner.borrow();
        let packed = inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        Ok(packed.remaining() as f64)
    }

    /// Total bytes added so far across all objects.
    pub fn length(&self) -> Result<f64, JsValue> {
        let inner = self.inner.borrow();
        let packed = inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        Ok(packed.length() as f64)
    }

    /// Optimal size of each slab in bytes.
    #[wasm_bindgen(js_name = "slabSize")]
    pub fn slab_size(&self) -> Result<f64, JsValue> {
        let inner = self.inner.borrow();
        let packed = inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        Ok(packed.slab_size() as f64)
    }

    /// Adds an object to the packed upload. Returns the number of bytes written.
    /// The object data is provided as a complete `Uint8Array`.
    pub async fn add(&self, data: Vec<u8>) -> Result<f64, JsValue> {
        let mut inner = self.inner.borrow_mut();
        let packed = inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        let cursor = Cursor::new(data);
        let n = packed.add(cursor).await.map_err(to_js_err)?;
        Ok(n as f64)
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(self) -> Result<Vec<PinnedObject>, JsValue> {
        let inner = self
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        let objects = run_local(inner.finalize()).await.map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Cancels the packed upload. This is a hard abort — in-flight shard
    /// uploads are abandoned and partially uploaded data is orphaned on hosts
    /// until it expires from temporary storage.
    pub fn cancel(&self) {
        self.inner.borrow_mut().take();
    }
}
