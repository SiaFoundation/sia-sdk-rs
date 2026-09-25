use crate::abi::*;
use sia_storage::{DownloadOptions, Object, Sdk};
use std::ffi::c_char;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::sync::CancellationToken;

#[repr(C)]
pub(crate) struct DownloadOptionsC {
    pub(crate) offset: u64,
    pub(crate) has_length: bool,
    pub(crate) length: u64,
    pub(crate) max_buffered_chunks: u64,
    pub(crate) on_shard: Option<ProgressFn>,
    pub(crate) userdata: usize,
}

pub(crate) struct FfiDownload {
    pub(crate) reader: Pin<Box<dyn AsyncRead + Send>>,
    pub(crate) pending_err: Option<std::io::Error>,
}

pub(crate) fn make_download_options(c: &DownloadOptionsC) -> DownloadOptions {
    let mut o = DownloadOptions {
        offset: c.offset,
        ..Default::default()
    };
    if c.has_length {
        o.length = Some(c.length);
    }
    if c.max_buffered_chunks > 0 {
        o.max_buffered_chunks = Some(c.max_buffered_chunks as usize);
    }
    if let Some(cb) = c.on_shard {
        let cb = CCallback {
            cb,
            userdata: c.userdata,
        };
        o = o.on_shard_downloaded(move |p| cb.invoke(p));
    }
    o
}

/// # Safety
/// - `out` must be non null and writable. It receives an owned handle.
pub(crate) unsafe fn start_download(
    reader: Pin<Box<dyn AsyncRead + Send>>,
    out: *mut *mut FfiDownload,
) -> i32 {
    unsafe {
        *out = Box::into_raw(Box::new(FfiDownload {
            reader,
            pending_err: None,
        }));
    }
    SIA_OK
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `opts` must be non null and point to an initialised struct.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_download_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_start(
    sdk: *const Sdk,
    obj: *const Object,
    opts: *const DownloadOptionsC,
    out: *mut *mut FfiDownload,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let (Some(sdk), Some(obj), Some(opts)) =
            (unsafe { (sdk.as_ref(), obj.as_ref(), opts.as_ref()) })
        else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let options = make_download_options(opts);
        // Download::new spawns tasks; enter the runtime context for the call.
        let _guard = runtime().enter();
        match sdk.download(obj, options) {
            Ok(dl) => unsafe { start_download(Box::pin(dl), out) },
            Err(e) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `dl` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_download_start` that has not been freed.
/// - `buf` must be writable for `cap` bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `n` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_read(
    dl: *mut FfiDownload,
    buf: *mut u8,
    cap: usize,
    cancel: *mut CancellationToken,
    n: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(dl) = (unsafe { dl.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if let Some(e) = dl.pending_err.take() {
            return set_typed_err(err, &e);
        }
        // Reporting zero bytes read would say EOF, so there is no honest
        // answer to give for a buffer with no room in it.
        if cap == 0 {
            return set_err(err, SIA_ERR, "read buffer is empty");
        }
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
        let reader = &mut dl.reader;
        let result = block_on(cancel, async {
            // Block for the first byte, then drain whatever is immediately
            // available to amortize the FFI crossing over large reads.
            let first = reader.read(buf).await?;
            if first == 0 || first == buf.len() {
                return Ok((first, None));
            }
            let mut total = first;
            let mut pending_err = None;
            std::future::poll_fn(|cx| {
                while total < buf.len() {
                    let mut rb = ReadBuf::new(&mut buf[total..]);
                    match reader.as_mut().poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let filled = rb.filled().len();
                            if filled == 0 {
                                break; // EOF; surfaced by the next read call
                            }
                            total += filled;
                        }
                        Poll::Ready(Err(e)) => {
                            pending_err = Some(e);
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
                Poll::Ready(())
            })
            .await;
            Ok::<_, std::io::Error>((total, pending_err))
        });
        match result {
            None => set_cancelled(err),
            Some(Ok((total, pending_err))) => {
                dl.pending_err = pending_err;
                unsafe { *n = total }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `dl` may be null. Otherwise it must come from `sia_download_start` and must not be used again
///   after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_free(dl: *mut FfiDownload) {
    if !dl.is_null() {
        drop(unsafe { Box::from_raw(dl) });
    }
}
