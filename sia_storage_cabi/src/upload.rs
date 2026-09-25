use crate::abi::*;
use crate::object::{sia_object_free, write_object_array};
use sia_storage::{Object, PackedUpload, PackedUploadOptions, Sdk, UploadOptions};
use std::ffi::c_char;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(crate) const UPLOAD_PIPE_CAPACITY: usize = 1 << 24; // 16 MiB

#[repr(C)]
pub(crate) struct UploadOptionsC {
    pub(crate) data_shards: u8,
    pub(crate) parity_shards: u8,
    pub(crate) set_redundancy: bool,
    pub(crate) max_buffered_slabs: u64,
    pub(crate) on_shard: Option<ProgressFn>,
    pub(crate) userdata: usize,
    /// When false, `start_offset` is ignored and the upload appends.
    pub(crate) has_start_offset: bool,
    /// Byte offset the reader's data overwrites from, rather than appending.
    /// Only the slabs covering the rewritten range are re-uploaded, but the
    /// finished object still has a new id, since an id is derived from its
    /// slabs.
    pub(crate) start_offset: u64,
}

pub(crate) struct FfiUpload {
    pub(crate) writer: Option<DuplexStream>,
    pub(crate) task: Option<JoinHandle<Result<Object, (i32, String)>>>,
}

pub(crate) struct FfiPacked {
    pub(crate) inner: Arc<tokio::sync::Mutex<Option<PackedUpload>>>,
    pub(crate) optimal_data_size: u64,
    pub(crate) writer: Option<DuplexStream>,
    pub(crate) add_task: Option<JoinHandle<Result<u64, (i32, String)>>>,
    /// Last values read while the lock was free. An add holds it from
    /// add_begin until EOF, which only the caller can send, so reading through
    /// the lock would deadlock the thread driving the add.
    pub(crate) remaining: AtomicU64,
    pub(crate) length: AtomicU64,
}

/// Reads one figure without waiting on an add. While an add holds the lock,
/// the snapshot from before it began is the honest answer.
fn packed_stat(up: &FfiPacked, snapshot: &AtomicU64, read: impl Fn(&PackedUpload) -> u64) -> u64 {
    match up.inner.try_lock() {
        Ok(guard) => {
            let value = guard.as_ref().map(read).unwrap_or(0);
            snapshot.store(value, Ordering::Relaxed);
            value
        }
        Err(_) => snapshot.load(Ordering::Relaxed),
    }
}

pub(crate) fn make_upload_options(c: &UploadOptionsC) -> UploadOptions {
    let mut o = UploadOptions::default();
    if c.set_redundancy {
        o.data_shards = c.data_shards;
        o.parity_shards = c.parity_shards;
    }
    if c.max_buffered_slabs > 0 {
        o.max_buffered_slabs = Some(c.max_buffered_slabs as usize);
    }
    if c.has_start_offset {
        o.start_offset = Some(c.start_offset);
    }
    if let Some(cb) = c.on_shard {
        let cb = CCallback {
            cb,
            userdata: c.userdata,
        };
        o = o.on_shard_uploaded(move |p| cb.invoke(p));
    }
    o
}

/// Packed uploads take their own options type, which carries no `start_offset`
/// because each object is appended into a shared slab rather than overwriting
/// a range of its own. A caller that sets one is refused rather than having it
/// silently dropped.
pub(crate) fn make_packed_upload_options(c: &UploadOptionsC) -> PackedUploadOptions {
    let mut o = PackedUploadOptions::default();
    if c.set_redundancy {
        o.data_shards = c.data_shards;
        o.parity_shards = c.parity_shards;
    }
    if c.max_buffered_slabs > 0 {
        o.max_buffered_slabs = Some(c.max_buffered_slabs as usize);
    }
    if let Some(cb) = c.on_shard {
        let cb = CCallback {
            cb,
            userdata: c.userdata,
        };
        o.shard_uploaded = Some(Arc::new(move |p| cb.invoke(p)));
    }
    o
}

/// Starts a streaming upload: the returned handle owns the write half of an
/// in-memory pipe and a task driving `upload` with the read half.
///
/// Always succeeds, so there is nothing to report through an `err` slot.
/// # Safety
/// - `out` must be non null and writable. It receives an owned handle.
pub(crate) unsafe fn start_upload<F, Fut>(out: *mut *mut FfiUpload, upload: F) -> i32
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: Future<Output = Result<Object, (i32, String)>> + Send + 'static,
{
    let (writer, reader) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
    let fut = upload(reader);
    let task = { runtime().spawn(fut) };
    unsafe {
        *out = Box::into_raw(Box::new(FfiUpload {
            writer: Some(writer),
            task: Some(task),
        }));
    }
    SIA_OK
}

/// Maps an already-joined upload task onto the C status protocol.
///
/// The join is deliberately left to the caller. Awaiting a `JoinHandle` by
/// value and then dropping it on cancellation detaches the task rather than
/// stopping it, so callers await `&mut` the handle they still own and decide
/// what to do with it themselves.
/// # Safety
/// - `out` must be non null and writable. On success it receives an owned object.
pub(crate) unsafe fn upload_result(
    joined: Result<Result<Object, (i32, String)>, tokio::task::JoinError>,
    out: *mut *mut Object,
    err: ErrOut,
) -> i32 {
    match joined {
        Ok(Ok(obj)) => {
            unsafe { *out = Box::into_raw(Box::new(obj)) }
            SIA_OK
        }
        Ok(Err((code, msg))) => set_err(err, code, msg),
        Err(join_err) if join_err.is_cancelled() => set_cancelled(err),
        Err(join_err) => set_err(err, SIA_ERR, join_err.to_string()),
    }
}

/// # Safety
/// - `out` must be non null and writable. It receives an owned handle.
pub(crate) unsafe fn start_packed(packed: PackedUpload, out: *mut *mut FfiPacked) -> i32 {
    let optimal_data_size = packed.optimal_data_size() as u64;
    unsafe {
        *out = Box::into_raw(Box::new(FfiPacked {
            inner: Arc::new(tokio::sync::Mutex::new(Some(packed))),
            optimal_data_size,
            writer: None,
            add_task: None,
            remaining: AtomicU64::new(optimal_data_size),
            length: AtomicU64::new(0),
        }));
    }
    SIA_OK
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which uploads into a fresh object. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object, that has not been freed. It is
///   borrowed, not consumed: the caller still frees it, and `sia_upload_finish` returns a
///   different object.
/// - `opts` must be non null and point to an initialised struct.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_upload_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_start(
    sdk: *const Sdk,
    obj: *const Object,
    opts: *const UploadOptionsC,
    out: *mut *mut FfiUpload,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let sdk = sdk.clone();
        let obj = match unsafe { obj.as_ref() } {
            Some(o) => o.clone(),
            None => Object::default(),
        };
        let Some(opts) = (unsafe { opts.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let options = make_upload_options(opts);
        if let Err(e) = options.validate() {
            return set_typed_err(err, &e);
        }
        unsafe {
            start_upload(out, move |reader| async move {
                sdk.upload(obj, reader, options)
                    .await
                    .map_err(|e| (status_for(&e), e.to_string()))
            })
        }
    })
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_upload_start` that has not been freed.
/// - `data` must be readable for `len` bytes. A `len` of 0 is a no-op and `data` is not read.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `written` may be null, which discards the count and leaves a cancelled write unresumable.
///   Otherwise it must be writable, and is written on every status including `SIA_ERR_CANCELLED`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_write(
    up: *mut FfiUpload,
    data: *const u8,
    len: usize,
    cancel: *mut CancellationToken,
    written: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if !written.is_null() {
            unsafe { *written = 0 }
        }
        let Some(writer) = up.writer.as_mut() else {
            return set_err(
                err,
                SIA_ERR_INVALID_STATE,
                "upload is no longer accepting data",
            );
        };
        // A C caller with nothing to send may well pass NULL, which
        // from_raw_parts rejects even for an empty slice.
        if len == 0 {
            return SIA_OK;
        }
        let buf = unsafe { std::slice::from_raw_parts(data, len) };

        // Written from inside the future and read after it is dropped, so a
        // cancelled write still reports how much of `buf` reached the pipe.
        // `write_all` cannot do this: it is not atomic, and dropping it mid
        // write loses the count, which leaves the caller unable to tell a
        // resumable partial write from a torn one.
        let mut done = 0usize;
        let outcome = {
            let done = &mut done;
            block_on(cancel, async move {
                while *done < buf.len() {
                    match writer.write(&buf[*done..]).await {
                        Ok(0) => {
                            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                        }
                        Ok(n) => *done += n,
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            })
        };
        if !written.is_null() {
            unsafe { *written = done }
        }

        match outcome {
            // The handle stays usable. `done` says where to resume, and the
            // upload is only torn if the caller ignores it and re-sends bytes
            // that already landed.
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(_)) => {
                // The pipe broke because the upload task ended; report its
                // real error instead of the write failure.
                up.writer = None;
                match up.task.take() {
                    Some(mut task) => {
                        // The task has already ended, so this join is
                        // immediate and needs no cancellation token.
                        let joined = runtime().block_on(&mut task);
                        let mut out = std::ptr::null_mut();
                        let code = unsafe { upload_result(joined, &raw mut out, err) };
                        if code == SIA_OK {
                            // Upload completed early without consuming all
                            // data; treat as an error to avoid silent loss.
                            unsafe { sia_object_free(out) }
                            return set_err(
                                err,
                                SIA_ERR,
                                "upload ended before all data was written",
                            );
                        }
                        code
                    }
                    None => set_err(err, SIA_ERR, "upload task already consumed"),
                }
            }
        }
    })
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_upload_start` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_finish(
    up: *mut FfiUpload,
    cancel: *mut CancellationToken,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if up.task.is_none() {
            return set_err(err, SIA_ERR_INVALID_STATE, "upload has already ended");
        }
        drop(up.writer.take()); // signal EOF

        // Awaited by reference so the handle stays owned here. Awaiting it by
        // value and dropping it on cancellation would detach the task, leaving
        // the upload to finish unobserved and strand sectors on hosts under an
        // object the caller never receives.
        let task = up.task.as_mut().expect("checked above");
        let Some(joined) = block_on(cancel, task) else {
            up.task.take().expect("checked above").abort();
            return set_cancelled(err);
        };
        up.task.take();
        unsafe { upload_result(joined, out, err) }
    })
}

/// # Safety
/// - `up` may be null. Otherwise it must come from `sia_upload_start` and must not be used again
///   after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_free(up: *mut FfiUpload) {
    if up.is_null() {
        return;
    }
    let up = unsafe { Box::from_raw(up) };
    if let Some(task) = &up.task {
        task.abort();
    }
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `opts` must be non null and point to an initialised struct.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_packed_upload_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_start(
    sdk: *const Sdk,
    opts: *const UploadOptionsC,
    out: *mut *mut FfiPacked,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let (Some(sdk), Some(opts)) = (unsafe { (sdk.as_ref(), opts.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if opts.has_start_offset {
            return set_err(
                err,
                SIA_ERR_INVALID_STATE,
                "a packed upload appends and cannot take a start offset",
            );
        }
        let options = make_packed_upload_options(opts);
        let _guard = runtime().enter();
        match sdk.upload_packed(options) {
            Ok(packed) => unsafe { start_packed(packed, out) },
            Err(e) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `up` may be null, which returns 0. Otherwise it must be a live handle from
///   `sia_packed_upload_start` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_remaining(up: *const FfiPacked) -> u64 {
    let Some(up) = (unsafe { up.as_ref() }) else {
        return 0;
    };
    packed_stat(up, &up.remaining, |p| p.remaining())
}

/// # Safety
/// - `up` may be null, which returns 0. Otherwise it must be a live handle from
///   `sia_packed_upload_start` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_length(up: *const FfiPacked) -> u64 {
    let Some(up) = (unsafe { up.as_ref() }) else {
        return 0;
    };
    packed_stat(up, &up.length, |p| p.length())
}

/// # Safety
/// - `up` may be null, which returns 0. Otherwise it must be a live handle from
///   `sia_packed_upload_start` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_optimal_data_size(up: *const FfiPacked) -> u64 {
    let Some(up) = (unsafe { up.as_ref() }) else {
        return 0;
    };
    up.optimal_data_size
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_packed_upload_start` that has not been freed.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_begin(
    up: *mut FfiPacked,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if up.writer.is_some() || up.add_task.is_some() {
            return set_err(err, SIA_ERR_INVALID_STATE, "an add is already in progress");
        }
        let (writer, reader) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let inner = up.inner.clone();
        let task = runtime().spawn(async move {
            let mut guard = inner.lock().await;
            let packed = guard.as_mut().ok_or_else(|| {
                (
                    SIA_ERR_INVALID_STATE,
                    "upload already finalized".to_string(),
                )
            })?;
            packed
                .add(reader)
                .await
                .map_err(|e| (status_for(&e), e.to_string()))
        });
        up.writer = Some(writer);
        up.add_task = Some(task);
        SIA_OK
    })
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_packed_upload_start` that has not been freed.
/// - `data` must be readable for `len` bytes. A `len` of 0 is a no-op and `data` is not read.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_write(
    up: *mut FfiPacked,
    data: *const u8,
    len: usize,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let Some(writer) = up.writer.as_mut() else {
            return set_err(err, SIA_ERR_INVALID_STATE, "no add in progress");
        };
        if len == 0 {
            return SIA_OK;
        }
        let buf = unsafe { std::slice::from_raw_parts(data, len) };
        match block_on(cancel, writer.write_all(buf)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(_)) => {
                up.writer = None;
                if up.add_task.is_none() {
                    return set_err(err, SIA_ERR, "add task already consumed");
                }
                // Owned across cancellation, as in add_finish above.
                let task = up.add_task.as_mut().expect("checked above");
                let Some(joined) = block_on(cancel, task) else {
                    return set_cancelled(err);
                };
                up.add_task.take();
                match joined {
                    Ok(Ok(_)) => set_err(err, SIA_ERR, "add ended before all data was written"),
                    Ok(Err((code, msg))) => set_err(err, code, msg),
                    Err(e) if e.is_cancelled() => set_cancelled(err),
                    Err(e) => set_typed_err(err, &e),
                }
            }
        }
    })
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_packed_upload_start` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `written` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_finish(
    up: *mut FfiPacked,
    cancel: *mut CancellationToken,
    written: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        drop(up.writer.take()); // signal EOF for this object
        if up.add_task.is_none() {
            return set_err(err, SIA_ERR_INVALID_STATE, "no add in progress");
        }

        // Awaited by reference, so cancelling leaves the task owned and the
        // state still "add in progress" for the next finish or abort to
        // consume. Dropping the handle would detach it, and whether the object
        // landed would then come down to whether the task or finalize reached
        // the mutex first, which the caller cannot observe.
        let task = up.add_task.as_mut().expect("checked above");
        let Some(joined) = block_on(cancel, task) else {
            return set_cancelled(err);
        };
        up.add_task.take();

        match joined {
            Ok(Ok(n)) => {
                unsafe { *written = n }
                SIA_OK
            }
            Ok(Err((code, msg))) => set_err(err, code, msg),
            Err(join_err) if join_err.is_cancelled() => set_cancelled(err),
            Err(join_err) => set_err(err, SIA_ERR, join_err.to_string()),
        }
    })
}

/// Abandons the add in progress, discarding the object it would have produced.
///
/// The writer is dropped first, which the add task sees as a clean end of
/// input, so it commits a short but otherwise valid object. That object is
/// then removed. The bytes it contributed stay in the packed stream and are
/// never referenced, which costs that much slab space but keeps every other
/// object's offsets intact.
///
/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_packed_upload_start` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_abort(
    up: *mut FfiPacked,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        drop(up.writer.take()); // signal EOF so the add task can finish
        if up.add_task.is_none() {
            return set_err(err, SIA_ERR_INVALID_STATE, "no add in progress");
        }

        // Awaited by reference, so a cancelled abort leaves the task owned
        // rather than detaching it. The writer is already gone, so the add is
        // finishing either way; keeping the handle lets a second abort observe
        // it and still drop the object. Aborting the task instead would leave
        // whether the object landed unknowable.
        let task = up.add_task.as_mut().expect("checked above");
        let Some(joined) = block_on(cancel, task) else {
            return set_cancelled(err);
        };
        up.add_task.take();

        // Only a task that succeeded pushed an object, so only then is there
        // one to remove. A failed add left the object list untouched.
        if !matches!(joined, Ok(Ok(_))) {
            return SIA_OK;
        }
        let inner = up.inner.clone();
        runtime().block_on(async move {
            if let Some(packed) = inner.lock().await.as_mut() {
                packed.discard_last();
            }
        });
        SIA_OK
    })
}

/// # Safety
/// - `up` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_packed_upload_start` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_objs` must be non null and writable. On success it receives an owned array that must be
///   released with `sia_object_array_free`.
/// - `out_len` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_finalize(
    up: *mut FfiPacked,
    cancel: *mut CancellationToken,
    out_objs: *mut *mut *mut Object,
    out_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(up) = (unsafe { up.as_mut() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if up.writer.is_some() || up.add_task.is_some() {
            return set_err(err, SIA_ERR_INVALID_STATE, "an add is still in progress");
        }
        let inner = up.inner.clone();
        let result = block_on(cancel, async move {
            let packed = inner.lock().await.take().ok_or_else(|| {
                (
                    SIA_ERR_INVALID_STATE,
                    "upload already finalized".to_string(),
                )
            })?;
            packed
                .finalize()
                .await
                .map_err(|e| (status_for(&e), e.to_string()))
        });
        match result {
            None => set_cancelled(err),
            Some(Ok(objects)) => {
                unsafe { write_object_array(objects, out_objs, out_len) }
                SIA_OK
            }
            Some(Err((code, msg))) => set_err(err, code, msg),
        }
    })
}

/// # Safety
/// - `up` may be null. Otherwise it must come from `sia_packed_upload_start` and must not be used
///   again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_free(up: *mut FfiPacked) {
    if up.is_null() {
        return;
    }
    let up = unsafe { Box::from_raw(up) };
    if let Some(task) = &up.add_task {
        task.abort();
    }
}
