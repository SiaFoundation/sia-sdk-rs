//! The machinery of crossing the boundary, as opposed to the modules around
//! it, which are about what the SDK does: status codes, error reporting, panic
//! containment, the async bridge, argument conversion, and the callbacks that
//! run outward into C.

use sia_storage::{AppKey, DownloadError, Hash256, QueueError, ShardProgress, UploadError};
use std::cell::Cell;
use std::ffi::{CStr, CString, c_char};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

pub(crate) const SIA_OK: i32 = 0;

pub(crate) const SIA_ERR: i32 = 1;

pub(crate) const SIA_ERR_UNAUTHORIZED: i32 = 2;

pub(crate) const SIA_ERR_USER_REJECTED: i32 = 3;

pub(crate) const SIA_ERR_REQUEST_EXPIRED: i32 = 4;

pub(crate) const SIA_ERR_CANCELLED: i32 = 5;

pub(crate) const SIA_ERR_INVALID_STATE: i32 = 6;

pub(crate) const SIA_ERR_OBJECT_NOT_ATTACHED: i32 = 7;

pub(crate) const SIA_ERR_KEY_MISMATCH: i32 = 8;

/// A required handle was missing. Returned instead of dereferencing it, so a
/// caller that passes null gets an error rather than undefined behaviour. A
/// handle that is present must still be live: this catches an absent handle,
/// not a dangling one. Out parameters are not checked; they are written only
/// on success, and passing a null one is undefined.
pub(crate) const SIA_ERR_INVALID_HANDLE: i32 = 9;

/// Not enough shards survived to satisfy the erasure coding.
pub(crate) const SIA_ERR_NOT_ENOUGH_SHARDS: i32 = 10;

/// Host selection ran out of candidates.
pub(crate) const SIA_ERR_NO_MORE_HOSTS: i32 = 11;

pub(crate) type ProgressFn = unsafe extern "C" fn(usize, *const ShardProgressC);

pub(crate) type LogFn = unsafe extern "C" fn(usize, i32, *const c_char, *const c_char);

#[repr(C)]
pub(crate) struct ShardProgressC {
    pub(crate) host_key: [u8; 32],
    pub(crate) shard_size: u64,
    pub(crate) shard_index: u64,
    pub(crate) slab_index: u64,
    pub(crate) elapsed_us: u64,
}

/// A C callback plus its userdata. The Go side guarantees the callback is
/// safe to invoke from any thread.
#[derive(Clone, Copy)]
pub(crate) struct CCallback {
    pub(crate) cb: ProgressFn,
    pub(crate) userdata: usize,
}

impl CCallback {
    pub(crate) fn invoke(&self, progress: ShardProgress) {
        let mut host_key = [0u8; 32];
        host_key.copy_from_slice(progress.host_key.as_ref());
        let c = ShardProgressC {
            host_key,
            shard_size: progress.shard_size as u64,
            shard_index: progress.shard_index as u64,
            slab_index: progress.slab_index as u64,
            elapsed_us: progress.elapsed.as_micros() as u64,
        };
        unsafe { (self.cb)(self.userdata, &raw const c) }
    }
}

pub(crate) struct CLogger {
    pub(crate) cb: LogFn,
    pub(crate) userdata: usize,
}

impl log::Log for CLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let target = CString::new(record.target()).unwrap_or_default();
        let msg = CString::new(record.args().to_string()).unwrap_or_default();
        unsafe {
            (self.cb)(
                self.userdata,
                record.level() as i32,
                target.as_ptr(),
                msg.as_ptr(),
            )
        }
    }

    fn flush(&self) {}
}

pub(crate) fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sia-storage-ffi")
            // The default 2 MiB worker stack has been observed to overflow
            // during chunk recovery; overflows on Rust-owned threads kill the
            // process with an untraceable SIGSEGV, so keep this generous.
            .thread_stack_size(8 << 20)
            .build()
            .expect("failed to build tokio runtime")
    })
}

/// The `char** err` out parameter, converted once per entry point so the
/// helpers that report through it are ordinary safe functions.
///
/// `Cell` rather than `&mut` because the same slot is written from several
/// arms of one call, and from a closure `guarded` also holds. It is `Copy` for
/// the same reason. A null `err` becomes `None` and every write is dropped.
#[derive(Clone, Copy)]
pub(crate) struct ErrOut<'a>(Option<&'a Cell<*mut c_char>>);

impl<'a> ErrOut<'a> {
    /// # Safety
    /// - `err` may be null. Otherwise it must be writable for `'a`, which for every caller here is
    ///   the body of one entry point.
    pub(crate) unsafe fn new(err: *mut *mut c_char) -> Self {
        // Cell<T> is repr(transparent) over T, so this is a layout preserving
        // cast, and as_ref gives None for null.
        Self(unsafe { err.cast::<Cell<*mut c_char>>().as_ref() })
    }

    /// Writes an owned message, replacing anything already there without
    /// freeing it, which matches what the header promises.
    pub(crate) fn set(self, msg: impl AsRef<str>) {
        if let Some(slot) = self.0 {
            let s = CString::new(msg.as_ref()).unwrap_or_default();
            slot.set(s.into_raw());
        }
    }
}

pub(crate) fn set_err(err: ErrOut, code: i32, msg: impl AsRef<str>) -> i32 {
    err.set(msg);
    code
}

pub(crate) fn set_cancelled(err: ErrOut) -> i32 {
    set_err(err, SIA_ERR_CANCELLED, "operation cancelled")
}

/// Returns the status code for one error, ignoring anything it wraps.
fn classify(e: &(dyn std::error::Error + 'static)) -> Option<i32> {
    if e.downcast_ref::<UploadError>()
        .is_some_and(|u| matches!(u, UploadError::NotEnoughShards(..)))
        || e.downcast_ref::<DownloadError>()
            .is_some_and(|d| matches!(d, DownloadError::NotEnoughShards(..)))
    {
        return Some(SIA_ERR_NOT_ENOUGH_SHARDS);
    }
    if e.downcast_ref::<QueueError>()
        .is_some_and(|q| matches!(q, QueueError::NoMoreHosts))
    {
        return Some(SIA_ERR_NO_MORE_HOSTS);
    }
    None
}

/// Classifies an error into a status code, so that the two failure modes
/// callers most need to branch on do not have to be recovered by matching on
/// the message text.
///
/// The whole chain is walked, because `QueueError::NoMoreHosts` surfaces
/// wrapped inside an upload or download error rather than on its own.
pub(crate) fn status_for(e: &(dyn std::error::Error + 'static)) -> i32 {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(code) = classify(err) {
            return code;
        }
        // io::Error::source returns the source of the error it wraps rather
        // than that error itself, so walking source alone steps straight over
        // the DownloadError that the AsyncRead impl boxes with
        // io::Error::other. Reach it with get_ref instead.
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            cur = Some(inner);
            continue;
        }
        cur = err.source();
    }
    SIA_ERR
}

/// set_err with the code taken from the error's type rather than assumed.
pub(crate) fn set_typed_err(err: ErrOut, e: &(dyn std::error::Error + 'static)) -> i32 {
    set_err(err, status_for(e), e.to_string())
}

/// Runs a future to completion on the shared runtime. Returns None if the
/// cancel token fires first.
pub(crate) fn block_on<F: Future>(cancel: Option<&CancellationToken>, fut: F) -> Option<F::Output> {
    let cancel = cancel.cloned();
    runtime().block_on(async move {
        match cancel {
            Some(tok) => tokio::select! {
                biased;
                _ = tok.cancelled() => None,
                out = fut => Some(out),
            },
            None => Some(fut.await),
        }
    })
}

/// Converts the optional paging arguments the C surface passes as a sentinel.
/// Zero means "let the indexer decide" for both, matching the Rust Option.
pub(crate) fn paging(offset: u64, limit: u64) -> (Option<u64>, Option<u64>) {
    ((offset > 0).then_some(offset), (limit > 0).then_some(limit))
}

/// # Safety
/// - `ptr` must be non null and point to 32 readable bytes.
pub(crate) unsafe fn hash_from_ptr(ptr: *const u8) -> Hash256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 32) });
    Hash256::new(buf)
}

/// # Safety
/// - `ptr` must be non null and point to 32 readable bytes.
pub(crate) unsafe fn seed_from_ptr(ptr: *const u8) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 32) });
    buf
}

/// # Safety
/// - `ptr` must be non null and point to 32 readable bytes.
pub(crate) unsafe fn app_key_from_ptr(ptr: *const u8) -> AppKey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 32) });
    AppKey::import(buf)
}

/// # Safety
/// - `ptr` must be non null and point to a NUL terminated string. The result borrows that string
///   rather than copying it, and `'a` is not tied to anything, so the caller has to choose a
///   lifetime the C side actually keeps the memory alive for. Every caller here uses it before
///   returning.
pub(crate) unsafe fn cstr<'a>(ptr: *const c_char) -> Result<&'a str, std::str::Utf8Error> {
    unsafe { CStr::from_ptr(ptr) }.to_str()
}

/// Wraps an FFI entry point body, converting panics into `SIA_ERR`.
pub(crate) fn guarded(err: ErrOut, body: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => set_err(err, SIA_ERR, "internal panic in sia_storage_cabi"),
    }
}

/// # Safety
/// - `s` must be non null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_set_logger(cb: Option<LogFn>, userdata: usize, max_level: i32) {
    let Some(cb) = cb else { return };
    let level = match max_level {
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    if log::set_boxed_logger(Box::new(CLogger { cb, userdata })).is_ok() {
        log::set_max_level(level);
    }
}

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_generate_recovery_phrase() -> *mut c_char {
    CString::new(sia_storage::generate_recovery_phrase())
        .unwrap_or_default()
        .into_raw()
}

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_new() -> *mut CancellationToken {
    Box::into_raw(Box::new(CancellationToken::new()))
}

/// # Safety
/// - `c` may be null, which makes the call uncancellable. Otherwise it must be a live token from
///   `sia_cancel_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_cancel(c: *mut CancellationToken) {
    if let Some(c) = unsafe { c.as_ref() } {
        c.cancel()
    }
}

/// # Safety
/// - `c` may be null, which makes the call uncancellable. Otherwise it must be a live token from
///   `sia_cancel_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_free(c: *mut CancellationToken) {
    if !c.is_null() {
        drop(unsafe { Box::from_raw(c) });
    }
}
