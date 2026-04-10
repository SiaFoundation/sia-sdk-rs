use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use sia_storage::PackedUpload as CorePackedUpload;
use tokio::io::{AsyncRead, ReadBuf};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::helpers::to_js_err;
use crate::object::PinnedObject;

/// An AsyncRead adapter over a JS ReadableStream.
struct ReadableStreamReader {
    reader: web_sys::ReadableStreamDefaultReader,
    pending: Option<JsFuture>,
    buf: Vec<u8>,
    pos: usize,
}

impl ReadableStreamReader {
    fn new(stream: web_sys::ReadableStream) -> Result<Self, JsValue> {
        let reader = stream
            .get_reader()
            .unchecked_into::<web_sys::ReadableStreamDefaultReader>();
        Ok(Self {
            reader,
            pending: None,
            buf: Vec::new(),
            pos: 0,
        })
    }
}

impl AsyncRead for ReadableStreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = std::cmp::min(buf.remaining(), self.buf.len() - self.pos);
            buf.put_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        if self.pending.is_none() {
            self.pending = Some(JsFuture::from(self.reader.read()));
        }

        let future = self.pending.as_mut().unwrap();
        match Pin::new(future).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.pending = None;
                Poll::Ready(Err(std::io::Error::other(format!(
                    "ReadableStream error: {e:?}"
                ))))
            }
            Poll::Ready(Ok(val)) => {
                self.pending = None;
                let done = js_sys::Reflect::get(&val, &"done".into())
                    .unwrap_or(JsValue::TRUE)
                    .as_bool()
                    .unwrap_or(true);
                if done {
                    return Poll::Ready(Ok(()));
                }
                let value = js_sys::Reflect::get(&val, &"value".into())
                    .map_err(|e| std::io::Error::other(format!("missing value: {e:?}")))?;
                let array: js_sys::Uint8Array = value.unchecked_into();
                let bytes = array.to_vec();
                if bytes.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() {
                    self.buf = bytes;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// A packed upload handle for efficiently uploading multiple objects
/// together. Objects are packed into shared slabs to avoid wasting storage.
///
/// ```js
/// const packed = sdk.uploadPacked();
/// await packed.add(file1);
/// await packed.add(file2);
/// const objects = await packed.finalize();
/// for (const obj of objects) await sdk.pinObject(obj);
/// ```
#[wasm_bindgen]
pub struct PackedUpload {
    inner: Rc<RefCell<Option<CorePackedUpload>>>,
}

impl PackedUpload {
    pub(crate) fn new(inner: CorePackedUpload) -> Self {
        Self {
            inner: Rc::new(RefCell::new(Some(inner))),
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

    /// Adds an object to the packed upload. Accepts a `File`, `Blob`, or
    /// `ReadableStream`. Returns the number of bytes written.
    ///
    /// ```js
    /// const packed = sdk.uploadPacked();
    /// await packed.add(file);
    /// await packed.add(blob);
    /// await packed.add(readableStream);
    /// ```
    pub async fn add(&self, source: JsValue) -> Result<f64, JsValue> {
        let stream: web_sys::ReadableStream = if source.has_type::<web_sys::ReadableStream>() {
            source.unchecked_into()
        } else if let Ok(blob) = source.dyn_into::<web_sys::Blob>() {
            blob.stream()
        } else {
            return Err(JsValue::from_str(
                "add() expects a File, Blob, or ReadableStream",
            ));
        };
        let reader = ReadableStreamReader::new(stream)?;
        let mut packed = self
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        let result = packed.add(reader).await.map_err(to_js_err);
        *self.inner.borrow_mut() = Some(packed);
        Ok(result? as f64)
    }

    /// Finalizes the packed upload and returns the resulting objects.
    /// Each object must be pinned separately with `sdk.pinObject()`.
    pub async fn finalize(self) -> Result<Vec<PinnedObject>, JsValue> {
        let inner = self
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("upload already finalized"))?;
        let objects = inner.finalize().await.map_err(to_js_err)?;
        Ok(objects.into_iter().map(PinnedObject).collect())
    }

    /// Cancels the packed upload. This is a hard abort — in-flight shard
    /// uploads are abandoned and partially uploaded data is orphaned on hosts
    /// until it expires from temporary storage.
    pub fn cancel(&self) {
        self.inner.borrow_mut().take();
    }
}
