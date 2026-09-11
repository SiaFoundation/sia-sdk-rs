//! C interface to the sia_storage crate, consumed by the Go SDK via cgo.
//!
//! See include/sia_storage.h for the C-side contract. Every extern function
//! is panic-safe: panics are caught and reported as SIA_ERR.

use std::ffi::{CStr, CString, c_char};
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;

#[cfg(feature = "mock")]
use sia_storage::mock::MockNetwork;
use sia_storage::{
    AppApiError, AppKey, AppMetadata, ApprovedState, Builder, BuilderError, DisconnectedState,
    DownloadOptions, Hash256, KeyRecord, KeyStats, Object, ObjectsCursor, PackedUpload,
    PackedUploadOptions, RequestingApprovalState, Sdk, SealedObject, ShardProgress, SharingError,
    SharingKey, SharingKeyOptions, UploadOptions,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const SIA_OK: i32 = 0;
const SIA_ERR: i32 = 1;
const SIA_ERR_UNAUTHORIZED: i32 = 2;
const SIA_ERR_USER_REJECTED: i32 = 3;
const SIA_ERR_REQUEST_EXPIRED: i32 = 4;
const SIA_ERR_CANCELLED: i32 = 5;
const SIA_ERR_INVALID_STATE: i32 = 6;
const SIA_ERR_OBJECT_NOT_ATTACHED: i32 = 7;
const SIA_ERR_KEY_MISMATCH: i32 = 8;

// Sized to keep several slabs' worth of data in flight so upload encoding is
// never starved waiting on the writer.
const UPLOAD_PIPE_CAPACITY: usize = 1 << 24; // 16 MiB

type ProgressFn = unsafe extern "C" fn(usize, *const ShardProgressC);
type LogFn = unsafe extern "C" fn(usize, i32, *const c_char, *const c_char);

#[repr(C)]
pub struct ShardProgressC {
    host_key: [u8; 32],
    shard_size: u64,
    shard_index: u64,
    slab_index: u64,
    elapsed_us: u64,
}

#[repr(C)]
pub struct UploadOptionsC {
    data_shards: u8,
    parity_shards: u8,
    set_redundancy: bool,
    max_buffered_slabs: u64,
    on_shard: Option<ProgressFn>,
    userdata: usize,
}

#[repr(C)]
pub struct DownloadOptionsC {
    offset: u64,
    has_length: bool,
    length: u64,
    max_buffered_chunks: u64,
    on_shard: Option<ProgressFn>,
    userdata: usize,
}

/// A C callback plus its userdata. The Go side guarantees the callback is
/// safe to invoke from any thread.
#[derive(Clone, Copy)]
struct CCallback {
    cb: ProgressFn,
    userdata: usize,
}

unsafe impl Send for CCallback {}
unsafe impl Sync for CCallback {}

impl CCallback {
    fn invoke(&self, progress: ShardProgress) {
        let mut host_key = [0u8; 32];
        host_key.copy_from_slice(progress.host_key.as_ref());
        let c = ShardProgressC {
            host_key,
            shard_size: progress.shard_size as u64,
            shard_index: progress.shard_index as u64,
            slab_index: progress.slab_index as u64,
            elapsed_us: progress.elapsed.as_micros() as u64,
        };
        unsafe { (self.cb)(self.userdata, &c) }
    }
}

struct CLogger {
    cb: LogFn,
    userdata: usize,
}

unsafe impl Send for CLogger {}
unsafe impl Sync for CLogger {}

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

enum BuilderState {
    Disconnected(Builder<DisconnectedState>),
    Requesting(Builder<RequestingApprovalState>),
    Approved(Builder<ApprovedState>),
    Consumed,
}

pub struct FfiBuilder(Mutex<BuilderState>);

pub struct FfiUpload {
    writer: Option<DuplexStream>,
    task: Option<JoinHandle<Result<Object, String>>>,
}

pub struct FfiDownload {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    pending_err: Option<std::io::Error>,
}

pub struct FfiPacked {
    inner: Arc<tokio::sync::Mutex<Option<PackedUpload>>>,
    optimal_data_size: u64,
    writer: Option<DuplexStream>,
    add_task: Option<JoinHandle<Result<u64, String>>>,
}

struct FfiEvent {
    id: [u8; 32],
    deleted: bool,
    updated_at_us: i64,
    object: Option<Box<Object>>,
}

pub struct FfiEvents(Vec<FfiEvent>);

pub struct FfiKeyRecords(Vec<KeyRecord>);

/// The indexer's snapshot of what a sharing key grants access to. Every field
/// is fixed width so the whole record crosses in one read rather than one call
/// per field.
#[repr(C)]
pub struct KeyStatsC {
    object_count: u64,
    object_size: u64,
    pinned_data: u64,
    pinned_size: u64,
    created_at_unix_us: i64,
    /// False when the key never expires, in which case expires_at is 0.
    has_expiry: bool,
    expires_at_unix_us: i64,
}

#[cfg(feature = "mock")]
pub struct FfiMock {
    network: MockNetwork,
}

#[derive(serde::Deserialize)]
struct AppMetadataIn {
    #[serde(rename = "appID")]
    id: Hash256,
    name: String,
    description: String,
    #[serde(rename = "serviceURL")]
    service_url: String,
    #[serde(rename = "logoURL")]
    logo_url: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

fn runtime() -> &'static Runtime {
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

fn set_err(err: *mut *mut c_char, code: i32, msg: impl AsRef<str>) -> i32 {
    if !err.is_null() {
        let s = CString::new(msg.as_ref()).unwrap_or_default();
        unsafe { *err = s.into_raw() }
    }
    code
}

fn set_cancelled(err: *mut *mut c_char) -> i32 {
    set_err(err, SIA_ERR_CANCELLED, "operation cancelled")
}

/// Runs a future to completion on the shared runtime. Returns None if the
/// cancel token fires first.
fn block_on<F: Future>(cancel: *mut CancellationToken, fut: F) -> Option<F::Output> {
    let cancel = if cancel.is_null() {
        None
    } else {
        Some(unsafe { (*cancel).clone() })
    };
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

fn builder_error(err: *mut *mut c_char, e: BuilderError) -> i32 {
    let code = match &e {
        BuilderError::RequestExpired => SIA_ERR_REQUEST_EXPIRED,
        BuilderError::Client(AppApiError::UserRejected) => SIA_ERR_USER_REJECTED,
        _ => SIA_ERR,
    };
    set_err(err, code, e.to_string())
}

/// Maps the sharing errors a caller can act on to their own status codes, so Go
/// can match them with errors.Is rather than on message text. Everything else
/// keeps its message under SIA_ERR.
fn sharing_error(err: *mut *mut c_char, e: SharingError) -> i32 {
    let code = match &e {
        SharingError::ObjectNotAttached => SIA_ERR_OBJECT_NOT_ATTACHED,
        SharingError::KeyMismatch => SIA_ERR_KEY_MISMATCH,
        _ => SIA_ERR,
    };
    set_err(err, code, e.to_string())
}

/// Converts the optional paging arguments the C surface passes as a sentinel.
/// Zero means "let the indexer decide" for both, matching the Rust Option.
fn paging(offset: u64, limit: u64) -> (Option<u64>, Option<u64>) {
    ((offset > 0).then_some(offset), (limit > 0).then_some(limit))
}

fn make_upload_options(c: &UploadOptionsC) -> UploadOptions {
    let mut o = UploadOptions::default();
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
        o = o.on_shard_uploaded(move |p| cb.invoke(p));
    }
    o
}

/// Packed uploads take their own options type, which carries no start_offset
/// because each object is appended into a shared slab rather than overwriting
/// a range of its own.
fn make_packed_upload_options(c: &UploadOptionsC) -> PackedUploadOptions {
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

fn make_download_options(c: &DownloadOptionsC) -> DownloadOptions {
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

fn hash_from_ptr(ptr: *const u8) -> Hash256 {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 32) });
    Hash256::new(buf)
}

fn app_key_from_ptr(ptr: *const u8) -> AppKey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, 32) });
    AppKey::import(buf)
}

fn cstr<'a>(ptr: *const c_char) -> Result<&'a str, std::str::Utf8Error> {
    unsafe { CStr::from_ptr(ptr) }.to_str()
}

/// Wraps an FFI entry point body, converting panics into SIA_ERR.
fn guarded(err: *mut *mut c_char, body: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => set_err(err, SIA_ERR, "internal panic in sia_storage_cabi"),
    }
}

/// Starts a streaming upload: the returned handle owns the write half of an
/// in-memory pipe and a task driving `upload` with the read half.
fn start_upload<F, Fut>(out: *mut *mut FfiUpload, err: *mut *mut c_char, upload: F) -> i32
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: Future<Output = Result<Object, String>> + Send + 'static,
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
    let _ = err;
    SIA_OK
}

/// Maps an already-joined upload task onto the C status protocol.
///
/// The join is deliberately left to the caller. Awaiting a `JoinHandle` by
/// value and then dropping it on cancellation detaches the task rather than
/// stopping it, so callers await `&mut` the handle they still own and decide
/// what to do with it themselves.
fn upload_result(
    joined: Result<Result<Object, String>, tokio::task::JoinError>,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    match joined {
        Ok(Ok(obj)) => {
            unsafe { *out = Box::into_raw(Box::new(obj)) }
            SIA_OK
        }
        Ok(Err(msg)) => set_err(err, SIA_ERR, msg),
        Err(join_err) if join_err.is_cancelled() => set_cancelled(err),
        Err(join_err) => set_err(err, SIA_ERR, join_err.to_string()),
    }
}

fn start_download(reader: Pin<Box<dyn AsyncRead + Send>>, out: *mut *mut FfiDownload) -> i32 {
    unsafe {
        *out = Box::into_raw(Box::new(FfiDownload {
            reader,
            pending_err: None,
        }));
    }
    SIA_OK
}

fn start_packed(packed: PackedUpload, out: *mut *mut FfiPacked) -> i32 {
    let optimal_data_size = packed.optimal_data_size() as u64;
    unsafe {
        *out = Box::into_raw(Box::new(FfiPacked {
            inner: Arc::new(tokio::sync::Mutex::new(Some(packed))),
            optimal_data_size,
            writer: None,
            add_task: None,
        }));
    }
    SIA_OK
}

// --- memory / util -----------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_generate_recovery_phrase() -> *mut c_char {
    CString::new(sia_storage::generate_recovery_phrase())
        .unwrap_or_default()
        .into_raw()
}

// --- cancellation ------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_new() -> *mut CancellationToken {
    Box::into_raw(Box::new(CancellationToken::new()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_cancel(c: *mut CancellationToken) {
    if !c.is_null() {
        unsafe { (*c).cancel() }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_cancel_free(c: *mut CancellationToken) {
    if !c.is_null() {
        drop(unsafe { Box::from_raw(c) });
    }
}

// --- builder -------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_new(
    indexer_url: *const c_char,
    app_meta_json: *const c_char,
    out: *mut *mut FfiBuilder,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let url = match cstr(indexer_url) {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid indexer url: {e}")),
        };
        let meta_json = match cstr(app_meta_json) {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid app metadata: {e}")),
        };
        let meta: AppMetadataIn = match serde_json::from_str(meta_json) {
            Ok(m) => m,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid app metadata: {e}")),
        };
        // AppMetadata requires 'static strings; a builder is created once per
        // connection attempt, so the leak is bounded and deliberate.
        let meta = AppMetadata {
            id: meta.id,
            name: Box::leak(meta.name.into_boxed_str()),
            description: Box::leak(meta.description.into_boxed_str()),
            service_url: Box::leak(meta.service_url.into_boxed_str()),
            logo_url: meta.logo_url.map(|s| &*Box::leak(s.into_boxed_str())),
            callback_url: meta.callback_url.map(|s| &*Box::leak(s.into_boxed_str())),
        };
        match Builder::new(url, meta) {
            Ok(b) => {
                unsafe {
                    *out = Box::into_raw(Box::new(FfiBuilder(Mutex::new(
                        BuilderState::Disconnected(b),
                    ))));
                }
                SIA_OK
            }
            Err(e) => builder_error(err, e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_free(b: *mut FfiBuilder) {
    if !b.is_null() {
        drop(unsafe { Box::from_raw(b) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_connect(
    b: *mut FfiBuilder,
    app_key: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let state = unsafe { (*b).0.lock() }.unwrap();
        let builder = match &*state {
            BuilderState::Disconnected(builder) => builder,
            _ => return set_err(err, SIA_ERR_INVALID_STATE, "builder is not disconnected"),
        };
        let key = app_key_from_ptr(app_key);
        match block_on(cancel, builder.connected(&key)) {
            None => set_cancelled(err),
            Some(Ok(Some(sdk))) => {
                unsafe { *out = Box::into_raw(Box::new(sdk)) }
                SIA_OK
            }
            Some(Ok(None)) => set_err(err, SIA_ERR_UNAUTHORIZED, "app key is not authorized"),
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_request_connection(
    b: *mut FfiBuilder,
    cancel: *mut CancellationToken,
    response_url: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let mut state = unsafe { (*b).0.lock() }.unwrap();
        let builder = match std::mem::replace(&mut *state, BuilderState::Consumed) {
            BuilderState::Disconnected(builder) => builder,
            other => {
                *state = other;
                return set_err(err, SIA_ERR_INVALID_STATE, "builder is not disconnected");
            }
        };
        match block_on(cancel, builder.request_connection()) {
            None => set_cancelled(err),
            Some(Ok(requesting)) => {
                let url = CString::new(requesting.response_url()).unwrap_or_default();
                *state = BuilderState::Requesting(requesting);
                unsafe { *response_url = url.into_raw() }
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_wait_for_approval(
    b: *mut FfiBuilder,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let mut state = unsafe { (*b).0.lock() }.unwrap();
        let builder = match std::mem::replace(&mut *state, BuilderState::Consumed) {
            BuilderState::Requesting(builder) => builder,
            other => {
                *state = other;
                return set_err(err, SIA_ERR_INVALID_STATE, "no connection request");
            }
        };
        match block_on(cancel, builder.wait_for_approval()) {
            None => set_cancelled(err),
            Some(Ok(approved)) => {
                *state = BuilderState::Approved(approved);
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_register(
    b: *mut FfiBuilder,
    mnemonic: *const c_char,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let phrase = match cstr(mnemonic) {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid mnemonic: {e}")),
        };
        let mut state = unsafe { (*b).0.lock() }.unwrap();
        let builder = match std::mem::replace(&mut *state, BuilderState::Consumed) {
            BuilderState::Approved(builder) => builder,
            other => {
                *state = other;
                return set_err(err, SIA_ERR_INVALID_STATE, "connection not approved");
            }
        };
        match block_on(cancel, builder.register(phrase)) {
            None => set_cancelled(err),
            Some(Ok(sdk)) => {
                unsafe { *out = Box::into_raw(Box::new(sdk)) }
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

// --- sdk -----------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_free(sdk: *mut Sdk) {
    if !sdk.is_null() {
        drop(unsafe { Box::from_raw(sdk) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_app_key(sdk: *const Sdk, out: *mut u8) {
    let seed = unsafe { &*sdk }.app_key().export();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&seed);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_account(
    sdk: *const Sdk,
    cancel: *mut CancellationToken,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        match block_on(cancel, sdk.account()) {
            None => set_cancelled(err),
            Some(Ok(account)) => match serde_json::to_string(&account) {
                Ok(js) => {
                    unsafe { *out_json = CString::new(js).unwrap_or_default().into_raw() }
                    SIA_OK
                }
                Err(e) => set_err(err, SIA_ERR, e.to_string()),
            },
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object(
    sdk: *const Sdk,
    id: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = hash_from_ptr(id);
        match block_on(cancel, sdk.object(&key)) {
            None => set_cancelled(err),
            Some(Ok(obj)) => {
                unsafe { *out = Box::into_raw(Box::new(obj)) }
                SIA_OK
            }
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object_events(
    sdk: *const Sdk,
    has_cursor: bool,
    after_unix_us: i64,
    after_id: *const u8,
    limit: u64,
    cancel: *mut CancellationToken,
    out: *mut *mut FfiEvents,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let cursor = if has_cursor {
            let after = match sia_storage::DateTime::from_timestamp_micros(after_unix_us) {
                Some(t) => t,
                None => return set_err(err, SIA_ERR, "invalid cursor timestamp"),
            };
            Some(ObjectsCursor {
                after,
                id: hash_from_ptr(after_id),
            })
        } else {
            None
        };
        let limit = if limit > 0 {
            Some(limit as usize)
        } else {
            None
        };
        match block_on(cancel, sdk.object_events(cursor, limit)) {
            None => set_cancelled(err),
            Some(Ok(events)) => {
                let events = events
                    .into_iter()
                    .map(|ev| {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(ev.id.as_ref());
                        FfiEvent {
                            id,
                            deleted: ev.deleted,
                            updated_at_us: ev.updated_at.timestamp_micros(),
                            object: ev.object.map(Box::new),
                        }
                    })
                    .collect();
                unsafe { *out = Box::into_raw(Box::new(FfiEvents(events))) }
                SIA_OK
            }
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_pin_object(
    sdk: *const Sdk,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let obj = unsafe { &*obj };
        match block_on(cancel, sdk.pin_object(obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_update_object_metadata(
    sdk: *const Sdk,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let obj = unsafe { &*obj };
        match block_on(cancel, sdk.update_object_metadata(obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_delete_object(
    sdk: *const Sdk,
    id: *const u8,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = hash_from_ptr(id);
        match block_on(cancel, sdk.delete_object(&key)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_prune_slabs(
    sdk: *const Sdk,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        match block_on(cancel, sdk.prune_slabs()) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object_share_url(
    sdk: *const Sdk,
    obj: *const Object,
    valid_until_unix_us: i64,
    out_url: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let obj = unsafe { &*obj };
        let valid_until = match sia_storage::DateTime::from_timestamp_micros(valid_until_unix_us) {
            Some(t) => t,
            None => return set_err(err, SIA_ERR, "invalid expiration timestamp"),
        };
        match sdk.object_share_url(obj, valid_until) {
            Ok(url) => {
                unsafe {
                    *out_url = CString::new(url.as_str()).unwrap_or_default().into_raw();
                }
                SIA_OK
            }
            Err(e) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object_from_share_url(
    sdk: *const Sdk,
    share_url: *const c_char,
    cancel: *mut CancellationToken,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let url = match cstr(share_url) {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid share url: {e}")),
        };
        match block_on(cancel, sdk.object_from_share_url(url)) {
            None => set_cancelled(err),
            Some(Ok(obj)) => {
                unsafe { *out = Box::into_raw(Box::new(obj)) }
                SIA_OK
            }
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

// --- object --------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_new() -> *mut Object {
    Box::into_raw(Box::new(Object::default()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_free(o: *mut Object) {
    if !o.is_null() {
        drop(unsafe { Box::from_raw(o) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_id(o: *const Object, out: *mut u8) {
    let id = unsafe { &*o }.id();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(id.as_ref());
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_size(o: *const Object) -> u64 {
    unsafe { &*o }.size()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_encoded_size(o: *const Object) -> u64 {
    unsafe { &*o }.encoded_size()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_created_at(o: *const Object) -> i64 {
    unsafe { &*o }.created_at.timestamp_micros()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_updated_at(o: *const Object) -> i64 {
    unsafe { &*o }.updated_at.timestamp_micros()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_metadata(o: *const Object, buf: *mut u8, cap: usize) -> usize {
    let meta = &unsafe { &*o }.metadata;
    if !buf.is_null() && cap >= meta.len() {
        unsafe { std::slice::from_raw_parts_mut(buf, meta.len()) }.copy_from_slice(meta);
    }
    meta.len()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_set_metadata(o: *mut Object, data: *const u8, len: usize) {
    let meta = if data.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    unsafe { &mut *o }.metadata = meta;
}

// --- object events -------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_events_len(evs: *const FfiEvents) -> usize {
    unsafe { &*evs }.0.len()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_events_at(
    evs: *mut FfiEvents,
    i: usize,
    id_out: *mut u8,
    deleted: *mut bool,
    updated_at_unix_us: *mut i64,
    obj: *mut *mut Object,
) -> bool {
    // Indexing out of range would panic, and a panic unwinding into C is
    // undefined behaviour that aborts the process in practice. There is no
    // error out-param here, so the bound is reported in the return value and
    // the out params are left untouched.
    let Some(ev) = unsafe { &mut *evs }.0.get_mut(i) else {
        return false;
    };
    unsafe {
        std::slice::from_raw_parts_mut(id_out, 32).copy_from_slice(&ev.id);
        *deleted = ev.deleted;
        *updated_at_unix_us = ev.updated_at_us;
        *obj = match ev.object.take() {
            Some(o) => Box::into_raw(o),
            None => std::ptr::null_mut(),
        };
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_events_free(evs: *mut FfiEvents) {
    if !evs.is_null() {
        drop(unsafe { Box::from_raw(evs) });
    }
}

// --- upload --------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_start(
    sdk: *const Sdk,
    obj: *const Object,
    opts: *const UploadOptionsC,
    out: *mut *mut FfiUpload,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk }.clone();
        let obj = unsafe { &*obj }.clone();
        let options = make_upload_options(unsafe { &*opts });
        if let Err(e) = options.validate() {
            return set_err(err, SIA_ERR, e.to_string());
        }
        start_upload(out, err, move |reader| async move {
            sdk.upload(obj, reader, options)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_write(
    up: *mut FfiUpload,
    data: *const u8,
    len: usize,
    cancel: *mut CancellationToken,
    written: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        if !written.is_null() {
            unsafe { *written = 0 }
        }
        let Some(writer) = up.writer.as_mut() else {
            return set_err(err, SIA_ERR_INVALID_STATE, "upload already finished");
        };
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
                        let Some(joined) = block_on(cancel, &mut task) else {
                            task.abort();
                            return set_cancelled(err);
                        };
                        let mut out = std::ptr::null_mut();
                        let code = upload_result(joined, &mut out, err);
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_upload_finish(
    up: *mut FfiUpload,
    cancel: *mut CancellationToken,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        if up.task.is_none() {
            return set_err(err, SIA_ERR_INVALID_STATE, "upload already finished");
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
        upload_result(joined, out, err)
    })
}

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

// --- download ------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_start(
    sdk: *const Sdk,
    obj: *const Object,
    opts: *const DownloadOptionsC,
    out: *mut *mut FfiDownload,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let obj = unsafe { &*obj };
        let options = make_download_options(unsafe { &*opts });
        // Download::new spawns tasks; enter the runtime context for the call.
        let _guard = runtime().enter();
        match sdk.download(obj, options) {
            Ok(dl) => start_download(Box::pin(dl), out),
            Err(e) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_read(
    dl: *mut FfiDownload,
    buf: *mut u8,
    cap: usize,
    cancel: *mut CancellationToken,
    n: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let dl = unsafe { &mut *dl };
        if let Some(e) = dl.pending_err.take() {
            return set_err(err, SIA_ERR, e.to_string());
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
            Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_download_free(dl: *mut FfiDownload) {
    if !dl.is_null() {
        drop(unsafe { Box::from_raw(dl) });
    }
}

// --- packed upload ---------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_start(
    sdk: *const Sdk,
    opts: *const UploadOptionsC,
    out: *mut *mut FfiPacked,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let options = make_packed_upload_options(unsafe { &*opts });
        let _guard = runtime().enter();
        match sdk.upload_packed(options) {
            Ok(packed) => start_packed(packed, out),
            Err(e) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_remaining(up: *const FfiPacked) -> u64 {
    let up = unsafe { &*up };
    runtime().block_on(async {
        up.inner
            .lock()
            .await
            .as_ref()
            .map(|p| p.remaining())
            .unwrap_or(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_length(up: *const FfiPacked) -> u64 {
    let up = unsafe { &*up };
    runtime().block_on(async {
        up.inner
            .lock()
            .await
            .as_ref()
            .map(|p| p.length())
            .unwrap_or(0)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_optimal_data_size(up: *const FfiPacked) -> u64 {
    unsafe { &*up }.optimal_data_size
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_begin(
    up: *mut FfiPacked,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        if up.writer.is_some() || up.add_task.is_some() {
            return set_err(err, SIA_ERR_INVALID_STATE, "an add is already in progress");
        }
        let (writer, reader) = tokio::io::duplex(UPLOAD_PIPE_CAPACITY);
        let inner = up.inner.clone();
        let task = runtime().spawn(async move {
            let mut guard = inner.lock().await;
            let packed = guard
                .as_mut()
                .ok_or_else(|| "upload already finalized".to_string())?;
            packed.add(reader).await.map_err(|e| e.to_string())
        });
        up.writer = Some(writer);
        up.add_task = Some(task);
        SIA_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_write(
    up: *mut FfiPacked,
    data: *const u8,
    len: usize,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        let Some(writer) = up.writer.as_mut() else {
            return set_err(err, SIA_ERR_INVALID_STATE, "no add in progress");
        };
        let buf = unsafe { std::slice::from_raw_parts(data, len) };
        match block_on(cancel, writer.write_all(buf)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(_)) => {
                up.writer = None;
                match up.add_task.take() {
                    Some(task) => match block_on(cancel, task) {
                        None => set_cancelled(err),
                        Some(Ok(Ok(_))) => {
                            set_err(err, SIA_ERR, "add ended before all data was written")
                        }
                        Some(Ok(Err(msg))) => set_err(err, SIA_ERR, msg),
                        Some(Err(e)) => set_err(err, SIA_ERR, e.to_string()),
                    },
                    None => set_err(err, SIA_ERR, "add task already consumed"),
                }
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_add_finish(
    up: *mut FfiPacked,
    cancel: *mut CancellationToken,
    written: *mut u64,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        drop(up.writer.take()); // signal EOF for this object
        match up.add_task.take() {
            Some(task) => match block_on(cancel, task) {
                None => set_cancelled(err),
                Some(Ok(Ok(n))) => {
                    unsafe { *written = n }
                    SIA_OK
                }
                Some(Ok(Err(msg))) => set_err(err, SIA_ERR, msg),
                Some(Err(join_err)) if join_err.is_cancelled() => set_cancelled(err),
                Some(Err(join_err)) => set_err(err, SIA_ERR, join_err.to_string()),
            },
            None => set_err(err, SIA_ERR_INVALID_STATE, "no add in progress"),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_packed_upload_finalize(
    up: *mut FfiPacked,
    cancel: *mut CancellationToken,
    out_objs: *mut *mut *mut Object,
    out_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let up = unsafe { &mut *up };
        if up.writer.is_some() || up.add_task.is_some() {
            return set_err(err, SIA_ERR_INVALID_STATE, "an add is still in progress");
        }
        let inner = up.inner.clone();
        let result = block_on(cancel, async move {
            let packed = inner
                .lock()
                .await
                .take()
                .ok_or_else(|| "upload already finalized".to_string())?;
            packed.finalize().await.map_err(|e| e.to_string())
        });
        match result {
            None => set_cancelled(err),
            Some(Ok(objects)) => {
                let ptrs: Vec<*mut Object> = objects
                    .into_iter()
                    .map(|o| Box::into_raw(Box::new(o)))
                    .collect();
                let mut ptrs = ptrs.into_boxed_slice();
                unsafe {
                    *out_len = ptrs.len();
                    *out_objs = ptrs.as_mut_ptr();
                }
                std::mem::forget(ptrs);
                SIA_OK
            }
            Some(Err(msg)) => set_err(err, SIA_ERR, msg),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_array_free(objs: *mut *mut Object, len: usize) {
    if !objs.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(objs, len)) });
    }
}

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

// --- sealed objects --------------------------------------------------------------
//
// A sealed object is the one type a caller sees inside rather than holds as an
// opaque handle, because consumers persist its fields into their own schema. It
// crosses as the JSON the indexer API already exchanges.

/// Seals an object under the account's app key and encodes it as JSON.
/// Free the result with sia_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_seal_json(
    sdk: *const Sdk,
    obj: *const Object,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let obj = unsafe { &*obj };
        let sealed = obj.seal(sdk.app_key());
        match serde_json::to_string(&sealed) {
            Ok(s) => {
                unsafe { *out_json = CString::new(s).unwrap_or_default().into_raw() }
                SIA_OK
            }
            Err(e) => set_err(err, SIA_ERR, format!("failed to encode sealed object: {e}")),
        }
    })
}

/// Decodes a sealed object from JSON and opens it with the account's app key,
/// verifying its signatures. This is how a caller that persisted the sealed
/// form gets a usable object back.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_from_sealed_json(
    sdk: *const Sdk,
    json: *const c_char,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let s = match cstr(json) {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid sealed object json: {e}")),
        };
        let sealed: SealedObject = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => return set_err(err, SIA_ERR, format!("failed to decode sealed object: {e}")),
        };
        match sealed.open(sdk.app_key()) {
            Ok(obj) => {
                unsafe { *out = Box::into_raw(Box::new(obj)) }
                SIA_OK
            }
            Err(e) => set_err(err, SIA_ERR, e.to_string()),
        }
    })
}

// --- sharing keys ----------------------------------------------------------------
//
// A sharing key grants read-only access to whatever the account attaches to it.
// The seed is the whole credential, so exporting one hands over access to every
// object attached to that key. Revoking detaches all of them at once.

fn key_stats_c(s: &KeyStats) -> KeyStatsC {
    KeyStatsC {
        object_count: s.object_count,
        object_size: s.object_size,
        pinned_data: s.pinned_data,
        pinned_size: s.pinned_size,
        created_at_unix_us: s.created_at.timestamp_micros(),
        has_expiry: s.expires_at.is_some(),
        expires_at_unix_us: s.expires_at.map(|t| t.timestamp_micros()).unwrap_or(0),
    }
}

/// Hands a vector of objects out as a heap array of owned handles, the shape
/// sia_object_array_free expects.
fn write_object_array(objects: Vec<Object>, out_objs: *mut *mut *mut Object, out_len: *mut usize) {
    let ptrs: Vec<*mut Object> = objects
        .into_iter()
        .map(|o| Box::into_raw(Box::new(o)))
        .collect();
    let mut ptrs = ptrs.into_boxed_slice();
    unsafe {
        *out_len = ptrs.len();
        *out_objs = ptrs.as_mut_ptr();
    }
    std::mem::forget(ptrs);
}

/// Rebuilds a sharing key from an exported seed. This is how a recipient, or a
/// process that persisted the seed, gets a usable credential back.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_import(seed: *const u8) -> *mut SharingKey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(seed, 32) });
    Box::into_raw(Box::new(SharingKey::import(buf)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_free(key: *mut SharingKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Writes the key's 32-byte seed, which is the entire credential. Treat the
/// output as secret.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_export(key: *const SharingKey, out: *mut u8) {
    let seed = unsafe { &*key }.export();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&seed);
}

/// Writes the key's public half, by which the indexer identifies it. Safe to
/// log or display.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_public_key(key: *const SharingKey, out: *mut u8) {
    let pk = unsafe { &*key }.public_key();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(pk.as_ref());
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_create_sharing_key(
    sdk: *const Sdk,
    description: *const c_char,
    has_expiry: bool,
    expires_at_unix_us: i64,
    cancel: *mut CancellationToken,
    out: *mut *mut SharingKey,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let description = match cstr(description) {
            Ok(s) => s.to_string(),
            Err(e) => return set_err(err, SIA_ERR, format!("invalid description: {e}")),
        };
        let expires_at = if has_expiry {
            match sia_storage::DateTime::from_timestamp_micros(expires_at_unix_us) {
                Some(t) => Some(t),
                None => return set_err(err, SIA_ERR, "invalid expiration timestamp"),
            }
        } else {
            None
        };
        let options = SharingKeyOptions {
            description,
            expires_at,
        };
        match block_on(cancel, sdk.create_sharing_key(options)) {
            None => set_cancelled(err),
            Some(Ok(key)) => {
                unsafe { *out = Box::into_raw(Box::new(key)) }
                SIA_OK
            }
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Fetches the indexer's current record for one key. *out_description receives
/// an owned string; free it with sia_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_sharing_key(
    sdk: *const Sdk,
    key: *const SharingKey,
    cancel: *mut CancellationToken,
    out_description: *mut *mut c_char,
    out_stats: *mut KeyStatsC,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = unsafe { &*key };
        match block_on(cancel, sdk.sharing_key(key)) {
            None => set_cancelled(err),
            Some(Ok(record)) => {
                let desc = CString::new(record.description).unwrap_or_default();
                unsafe {
                    *out_description = desc.into_raw();
                    *out_stats = key_stats_c(&record.stats);
                }
                SIA_OK
            }
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Lists the account's sharing keys. Pass 0 for offset or limit to use the
/// indexer's default paging.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_sharing_keys(
    sdk: *const Sdk,
    offset: u64,
    limit: u64,
    cancel: *mut CancellationToken,
    out: *mut *mut FfiKeyRecords,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let (offset, limit) = paging(offset, limit);
        match block_on(cancel, sdk.sharing_keys(offset, limit)) {
            None => set_cancelled(err),
            Some(Ok(records)) => {
                unsafe { *out = Box::into_raw(Box::new(FfiKeyRecords(records))) }
                SIA_OK
            }
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_len(recs: *const FfiKeyRecords) -> usize {
    unsafe { &*recs }.0.len()
}

/// Copies the record at `i` out. *out_key receives an owned key handle, freed
/// with sia_sharing_key_free, and *out_description an owned string, freed with
/// sia_string_free. Returns false when `i` is out of range, leaving the out
/// params untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_at(
    recs: *const FfiKeyRecords,
    i: usize,
    out_key: *mut *mut SharingKey,
    out_description: *mut *mut c_char,
    out_stats: *mut KeyStatsC,
) -> bool {
    let recs = unsafe { &*recs };
    let Some(record) = recs.0.get(i) else {
        return false;
    };
    let desc = CString::new(record.description.clone()).unwrap_or_default();
    unsafe {
        *out_key = Box::into_raw(Box::new(record.key.clone()));
        *out_description = desc.into_raw();
        *out_stats = key_stats_c(&record.stats);
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_free(recs: *mut FfiKeyRecords) {
    if !recs.is_null() {
        drop(unsafe { Box::from_raw(recs) });
    }
}

/// Attaches an object to a sharing key, re-sealing its keys under that key.
/// Attaching an object already attached replaces its sealed keys, so a failed
/// call can be retried with the same object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_share_object(
    sdk: *const Sdk,
    key: *const SharingKey,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = unsafe { &*key };
        let obj = unsafe { &*obj };
        match block_on(cancel, sdk.share_object(key, obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Lists and decrypts the objects attached to a key. *out_objs receives a heap
/// array of owned handles; free the array with sia_object_array_free. Pass 0
/// for offset or limit to use the indexer's default paging.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_shared_objects(
    sdk: *const Sdk,
    key: *const SharingKey,
    offset: u64,
    limit: u64,
    cancel: *mut CancellationToken,
    out_objs: *mut *mut *mut Object,
    out_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = unsafe { &*key };
        let (offset, limit) = paging(offset, limit);
        match block_on(cancel, sdk.shared_objects(key, offset, limit)) {
            None => set_cancelled(err),
            Some(Ok(objects)) => {
                write_object_array(objects, out_objs, out_len);
                SIA_OK
            }
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Detaches one object from a key. Returns SIA_ERR_OBJECT_NOT_ATTACHED when the
/// object was not attached to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_unshare_object(
    sdk: *const Sdk,
    key: *const SharingKey,
    object_id: *const u8,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = unsafe { &*key };
        let id = hash_from_ptr(object_id);
        match block_on(cancel, sdk.unshare_object(key, &id)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Revokes a key, detaching every object attached to it at once. Downloads
/// already in flight can keep reading from hosts for up to five more minutes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_revoke_sharing_key(
    sdk: *const Sdk,
    key: *const SharingKey,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let sdk = unsafe { &*sdk };
        let key = unsafe { &*key };
        match block_on(cancel, sdk.revoke_sharing_key(key)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

// --- mock ------------------------------------------------------------------------
//
// Compiled only with the `mock` cargo feature. As of sia_storage 0.11 that
// feature is additive, so it leaves the real host transport in place and adds
// an in-memory one alongside it. sia_mock_sdk hands back an ordinary Sdk backed
// by in-process hosts, which means every other function in this library runs
// the same code path under test that it runs in production.

#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_new(num_hosts: usize) -> *mut FfiMock {
    let network = MockNetwork::new();
    network.add_hosts(num_hosts);
    Box::into_raw(Box::new(FfiMock { network }))
}

#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_free(m: *mut FfiMock) {
    if !m.is_null() {
        drop(unsafe { Box::from_raw(m) });
    }
}

/// Builds an Sdk served by the mock network. The result is an ordinary handle
/// and is released with sia_sdk_free like any other.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_sdk(
    m: *const FfiMock,
    app_key: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, || {
        let m = unsafe { &*m };
        let key = app_key_from_ptr(app_key);
        match block_on(cancel, m.network.sdk(key)) {
            None => set_cancelled(err),
            Some(Ok(sdk)) => {
                unsafe { *out = Box::into_raw(Box::new(sdk)) }
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

/// Drops every sector the mock hosts hold, so a download of an object that was
/// already uploaded fails the way it would if the hosts had lost the data.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_clear_sectors(m: *const FfiMock) {
    unsafe { &*m }.network.clear_sectors();
}

#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_pinned_slabs(m: *const FfiMock) -> usize {
    unsafe { &*m }.network.pinned_slabs()
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;

    /// Consumes an out-param error message so a failed assertion can report
    /// what Rust actually said rather than just the status code.
    unsafe fn take_err(err: *mut c_char) -> String {
        if err.is_null() {
            return "no message".to_string();
        }
        unsafe { CString::from_raw(err) }
            .to_string_lossy()
            .into_owned()
    }

    fn default_upload_options() -> UploadOptionsC {
        UploadOptionsC {
            data_shards: 0,
            parity_shards: 0,
            set_redundancy: false,
            max_buffered_slabs: 0,
            on_shard: None,
            userdata: 0,
        }
    }

    fn default_download_options() -> DownloadOptionsC {
        DownloadOptionsC {
            offset: 0,
            has_length: false,
            length: 0,
            max_buffered_chunks: 0,
            on_shard: None,
            userdata: 0,
        }
    }

    /// Streams a payload out through sia_upload_* and back in through
    /// sia_download_*, against in-process hosts. This is the only test that
    /// covers the streaming entry points the Go SDK is built on, and it runs
    /// the same Sdk code path production runs.
    #[test]
    fn mock_upload_download_roundtrip() {
        unsafe {
            let mock = sia_mock_new(40);
            assert!(!mock.is_null());

            let seed = [7u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &mut sdk,
                &mut err,
            );
            assert_eq!(code, SIA_OK, "sia_mock_sdk: {}", take_err(err));
            assert!(!sdk.is_null());

            let obj = sia_object_new();
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_upload_start(sdk, obj, &opts, &mut up, &mut err);
            assert_eq!(code, SIA_OK, "sia_upload_start: {}", take_err(err));

            // Larger than one 4 MiB sector so the payload spans several shards
            // and the erasure coder actually runs.
            let payload: Vec<u8> = (0..(9 << 20)).map(|i| (i % 251) as u8).collect();
            let mut err = std::ptr::null_mut();
            let mut wrote = 0usize;
            let code = sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &mut wrote,
                &mut err,
            );
            assert_eq!(code, SIA_OK, "sia_upload_write: {}", take_err(err));
            assert_eq!(
                wrote,
                payload.len(),
                "a successful write must report it all"
            );

            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err);
            assert_eq!(code, SIA_OK, "sia_upload_finish: {}", take_err(err));
            sia_upload_free(up);
            assert!(!uploaded.is_null());
            assert_eq!(sia_object_size(uploaded), payload.len() as u64);

            let dopts = default_download_options();
            let mut dl = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_download_start(sdk, uploaded, &dopts, &mut dl, &mut err);
            assert_eq!(code, SIA_OK, "sia_download_start: {}", take_err(err));

            let mut got = Vec::with_capacity(payload.len());
            let mut buf = vec![0u8; 256 << 10];
            loop {
                let mut n = 0usize;
                let mut err = std::ptr::null_mut();
                let code = sia_download_read(
                    dl,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::null_mut(),
                    &mut n,
                    &mut err,
                );
                assert_eq!(code, SIA_OK, "sia_download_read: {}", take_err(err));
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            sia_download_free(dl);

            assert_eq!(got.len(), payload.len(), "downloaded a different length");
            assert!(got == payload, "downloaded bytes differ from the upload");

            sia_object_free(uploaded);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// A download of an object whose sectors the hosts have dropped must fail
    /// rather than return short or hang. This is the failure path the Go side
    /// maps onto ErrNotEnoughShards.
    #[test]
    fn download_fails_when_sectors_are_gone() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [9u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &mut sdk,
                &mut err,
            );
            assert_eq!(code, SIA_OK, "sia_mock_sdk: {}", take_err(err));

            let obj = sia_object_new();
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_start(sdk, obj, &opts, &mut up, &mut err),
                SIA_OK,
                "sia_upload_start: {}",
                take_err(err)
            );

            let payload = vec![3u8; 5 << 20];
            let mut err = std::ptr::null_mut();
            let mut wrote = 0usize;
            assert_eq!(
                sia_upload_write(
                    up,
                    payload.as_ptr(),
                    payload.len(),
                    std::ptr::null_mut(),
                    &mut wrote,
                    &mut err
                ),
                SIA_OK,
                "sia_upload_write: {}",
                take_err(err)
            );
            assert_eq!(
                wrote,
                payload.len(),
                "a successful write must report it all"
            );

            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err),
                SIA_OK,
                "sia_upload_finish: {}",
                take_err(err)
            );
            sia_upload_free(up);

            sia_mock_clear_sectors(mock);

            let dopts = default_download_options();
            let mut dl = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_start(sdk, uploaded, &dopts, &mut dl, &mut err),
                SIA_OK,
                "sia_download_start: {}",
                take_err(err)
            );

            let mut buf = vec![0u8; 256 << 10];
            let read_err = loop {
                let mut n = 0usize;
                let mut err = std::ptr::null_mut();
                let code = sia_download_read(
                    dl,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::null_mut(),
                    &mut n,
                    &mut err,
                );
                if code != SIA_OK {
                    break take_err(err);
                }
                assert_ne!(n, 0, "download reported a clean EOF after sector loss");
            };
            sia_download_free(dl);

            assert!(
                read_err.contains("not enough shards"),
                "expected a shard recovery failure, got {read_err}"
            );

            sia_object_free(uploaded);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// The sharing key handle is pure key derivation with no indexer involved,
    /// so the whole import, export and free lifecycle is testable here. Export
    /// hands back the credential, so a mismatch would leak the wrong key.
    #[test]
    fn sharing_key_import_export_roundtrip() {
        unsafe {
            let seed = [0x5au8; 32];
            let key = sia_sharing_key_import(seed.as_ptr());
            assert!(!key.is_null());

            let mut exported = [0u8; 32];
            sia_sharing_key_export(key, exported.as_mut_ptr());
            assert_eq!(exported, seed, "export must return the imported seed");

            let mut pk = [0u8; 32];
            sia_sharing_key_public_key(key, pk.as_mut_ptr());
            assert_ne!(pk, [0u8; 32], "public half must be derived, not zero");
            assert_ne!(pk, seed, "public half must not be the seed itself");

            // The same seed must derive the same key, or a recipient handed an
            // exported seed would not reach the same objects.
            let key2 = sia_sharing_key_import(seed.as_ptr());
            let mut pk2 = [0u8; 32];
            sia_sharing_key_public_key(key2, pk2.as_mut_ptr());
            assert_eq!(pk, pk2, "the same seed must derive the same key");

            sia_sharing_key_free(key);
            sia_sharing_key_free(key2);
            sia_sharing_key_free(std::ptr::null_mut());
        }
    }

    /// Drives the sharing key lifecycle against the mock, which now implements
    /// the indexer side of it. Every call here reaches real code rather than an
    /// error path, so this covers the entry points a binding needs in order and
    /// checks the ownership rules on the ones that hand back allocations.
    #[test]
    fn sharing_key_lifecycle_against_the_mock() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [13u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_mock_sdk(
                    mock,
                    seed.as_ptr(),
                    std::ptr::null_mut(),
                    &mut sdk,
                    &mut err
                ),
                SIA_OK,
                "sia_mock_sdk: {}",
                take_err(err)
            );

            let desc = CString::new("test key").unwrap();
            let mut key = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_sdk_create_sharing_key(
                    sdk,
                    desc.as_ptr(),
                    false,
                    0,
                    std::ptr::null_mut(),
                    &mut key,
                    &mut err,
                ),
                SIA_OK,
                "sia_sdk_create_sharing_key: {}",
                take_err(err)
            );
            assert!(!key.is_null(), "a created key must come back as a handle");

            // The seed is the whole credential, so exporting one and importing
            // it again has to yield the same public key.
            let mut exported = [0u8; 32];
            sia_sharing_key_export(key, exported.as_mut_ptr());
            let reimported = sia_sharing_key_import(exported.as_ptr());
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            sia_sharing_key_public_key(key, a.as_mut_ptr());
            sia_sharing_key_public_key(reimported, b.as_mut_ptr());
            assert_eq!(a, b, "an exported seed must reimport to the same key");
            sia_sharing_key_free(reimported);

            let mut out_desc = std::ptr::null_mut();
            let mut stats = std::mem::zeroed::<KeyStatsC>();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_sdk_sharing_key(
                    sdk,
                    key,
                    std::ptr::null_mut(),
                    &mut out_desc,
                    &mut stats,
                    &mut err
                ),
                SIA_OK,
                "sia_sdk_sharing_key: {}",
                take_err(err)
            );
            assert_eq!(
                CStr::from_ptr(out_desc).to_str().unwrap(),
                "test key",
                "the description must survive the round trip"
            );
            sia_string_free(out_desc);

            let mut recs = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_sdk_sharing_keys(sdk, 0, 10, std::ptr::null_mut(), &mut recs, &mut err),
                SIA_OK,
                "sia_sdk_sharing_keys: {}",
                take_err(err)
            );
            assert_eq!(sia_key_records_len(recs), 1, "the account has one key");

            let mut listed_key = std::ptr::null_mut();
            let mut listed_desc = std::ptr::null_mut();
            let mut listed_stats = std::mem::zeroed::<KeyStatsC>();
            assert!(
                sia_key_records_at(
                    recs,
                    0,
                    &mut listed_key,
                    &mut listed_desc,
                    &mut listed_stats
                ),
                "index 0 is in range"
            );
            assert!(
                !sia_key_records_at(
                    recs,
                    1,
                    &mut listed_key,
                    &mut listed_desc,
                    &mut listed_stats
                ),
                "an out of range index must report false rather than panic"
            );
            sia_sharing_key_free(listed_key);
            sia_string_free(listed_desc);
            sia_key_records_free(recs);

            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_sdk_revoke_sharing_key(sdk, key, std::ptr::null_mut(), &mut err),
                SIA_OK,
                "sia_sdk_revoke_sharing_key: {}",
                take_err(err)
            );

            sia_sharing_key_free(key);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// The sealed object crossing has to survive a full round trip, because the
    /// JSON is what a caller persists. Sealing, encoding, decoding and opening
    /// must return an object that still downloads, or a stored object becomes
    /// unreadable after a restart.
    #[test]
    fn sealed_object_json_round_trips() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [31u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_mock_sdk(
                    mock,
                    seed.as_ptr(),
                    std::ptr::null_mut(),
                    &mut sdk,
                    &mut err
                ),
                SIA_OK,
                "sia_mock_sdk: {}",
                take_err(err)
            );

            // An uploaded object, so the sealed form carries real slabs and
            // sectors rather than an empty slab list.
            let obj = sia_object_new();
            let meta = b"round trip metadata".to_vec();
            sia_object_set_metadata(obj, meta.as_ptr(), meta.len());
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_start(sdk, obj, &opts, &mut up, &mut err),
                SIA_OK,
                "sia_upload_start: {}",
                take_err(err)
            );
            let payload = vec![17u8; 5 << 20];
            let mut wrote = 0usize;
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_write(
                    up,
                    payload.as_ptr(),
                    payload.len(),
                    std::ptr::null_mut(),
                    &mut wrote,
                    &mut err
                ),
                SIA_OK,
                "sia_upload_write: {}",
                take_err(err)
            );
            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err),
                SIA_OK,
                "sia_upload_finish: {}",
                take_err(err)
            );
            sia_upload_free(up);

            let mut json = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_object_seal_json(sdk, uploaded, &mut json, &mut err),
                SIA_OK,
                "sia_object_seal_json: {}",
                take_err(err)
            );
            let encoded = CString::from_raw(json).to_string_lossy().into_owned();

            // The field names are the wire contract a consumer decodes by name.
            for field in [
                "encryptedDataKey",
                "slabs",
                "dataSignature",
                "metadataSignature",
                "createdAt",
                "updatedAt",
            ] {
                assert!(
                    encoded.contains(&format!("\"{field}\"")),
                    "sealed json is missing {field}, which consumers decode by name"
                );
            }

            let cjson = CString::new(encoded).unwrap();
            let mut reopened = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_object_from_sealed_json(sdk, cjson.as_ptr(), &mut reopened, &mut err),
                SIA_OK,
                "sia_object_from_sealed_json: {}",
                take_err(err)
            );

            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            sia_object_id(uploaded, a.as_mut_ptr());
            sia_object_id(reopened, b.as_mut_ptr());
            assert_eq!(a, b, "the round tripped object has a different id");
            assert_eq!(
                sia_object_size(uploaded),
                sia_object_size(reopened),
                "size changed across the round trip"
            );

            let n = sia_object_metadata(reopened, std::ptr::null_mut(), 0);
            let mut got = vec![0u8; n];
            sia_object_metadata(reopened, got.as_mut_ptr(), n);
            assert_eq!(got, meta, "metadata did not survive the round trip");

            // The reopened object must still be usable, not merely equal.
            let dopts = default_download_options();
            let mut dl = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_start(sdk, reopened, &dopts, &mut dl, &mut err),
                SIA_OK,
                "a round tripped object could not be downloaded: {}",
                take_err(err)
            );
            let mut got = Vec::with_capacity(payload.len());
            let mut buf = vec![0u8; 256 << 10];
            loop {
                let mut n = 0usize;
                let mut err = std::ptr::null_mut();
                assert_eq!(
                    sia_download_read(
                        dl,
                        buf.as_mut_ptr(),
                        buf.len(),
                        std::ptr::null_mut(),
                        &mut n,
                        &mut err
                    ),
                    SIA_OK,
                    "sia_download_read: {}",
                    take_err(err)
                );
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            sia_download_free(dl);
            assert!(got == payload, "downloaded bytes differ after a round trip");

            sia_object_free(reopened);
            sia_object_free(uploaded);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// A cancelled write must report how many bytes reached the pipe and must
    /// leave the handle usable, or a caller cannot tell a resumable partial
    /// write from a torn one and will silently corrupt the object by resending
    /// bytes that already landed.
    #[test]
    fn cancelled_write_reports_progress_and_leaves_the_upload_resumable() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [21u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_mock_sdk(
                    mock,
                    seed.as_ptr(),
                    std::ptr::null_mut(),
                    &mut sdk,
                    &mut err
                ),
                SIA_OK,
                "sia_mock_sdk: {}",
                take_err(err)
            );

            let obj = sia_object_new();
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_start(sdk, obj, &opts, &mut up, &mut err),
                SIA_OK,
                "sia_upload_start: {}",
                take_err(err)
            );

            let payload = vec![4u8; 5 << 20];

            // An already cancelled token makes the outcome deterministic: the
            // biased select takes the cancel branch before any byte moves.
            let cancel = sia_cancel_new();
            sia_cancel_cancel(cancel);
            let mut wrote = usize::MAX;
            let mut err = std::ptr::null_mut();
            let code = sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                cancel,
                &mut wrote,
                &mut err,
            );
            let msg = take_err(err);
            assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");
            assert_eq!(wrote, 0, "a write cancelled before starting moved no bytes");
            sia_cancel_free(cancel);

            // The handle survived, so the caller can resume from `wrote`.
            let mut wrote = 0usize;
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_write(
                    up,
                    payload.as_ptr(),
                    payload.len(),
                    std::ptr::null_mut(),
                    &mut wrote,
                    &mut err
                ),
                SIA_OK,
                "the upload was not resumable after a cancelled write: {}",
                take_err(err)
            );
            assert_eq!(wrote, payload.len());

            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err),
                SIA_OK,
                "sia_upload_finish: {}",
                take_err(err)
            );
            assert_eq!(sia_object_size(uploaded), payload.len() as u64);

            sia_upload_free(up);
            sia_object_free(uploaded);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// Cancelling finish must consume the task rather than detach it. A
    /// detached upload runs to completion with nobody observing it, stranding
    /// sectors on hosts under an object the caller never receives.
    #[test]
    fn cancelled_finish_consumes_the_upload() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [23u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_mock_sdk(
                    mock,
                    seed.as_ptr(),
                    std::ptr::null_mut(),
                    &mut sdk,
                    &mut err
                ),
                SIA_OK,
                "sia_mock_sdk: {}",
                take_err(err)
            );

            let obj = sia_object_new();
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_start(sdk, obj, &opts, &mut up, &mut err),
                SIA_OK,
                "sia_upload_start: {}",
                take_err(err)
            );

            let cancel = sia_cancel_new();
            sia_cancel_cancel(cancel);
            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let code = sia_upload_finish(up, cancel, &mut uploaded, &mut err);
            let msg = take_err(err);
            assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");
            assert!(
                uploaded.is_null(),
                "the out param must be untouched on cancellation"
            );
            sia_cancel_free(cancel);

            // The task was taken and aborted, so the handle is spent rather
            // than left holding a live upload nobody is watching.
            let mut err = std::ptr::null_mut();
            let code = sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err);
            let msg = take_err(err);
            assert_eq!(
                code, SIA_ERR_INVALID_STATE,
                "a cancelled upload must not be finishable again, got {msg}"
            );

            sia_upload_free(up);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }

    /// An out of range index must be reported rather than panicking, since a
    /// panic unwinding into C is undefined behaviour and aborts the process.
    #[test]
    fn events_at_rejects_out_of_range() {
        unsafe {
            let evs = Box::into_raw(Box::new(FfiEvents(Vec::new())));
            assert_eq!(sia_events_len(evs), 0);

            let mut id = [0u8; 32];
            let mut deleted = false;
            let mut updated_at = 0i64;
            let mut obj = std::ptr::null_mut();
            assert!(
                !sia_events_at(
                    evs,
                    0,
                    id.as_mut_ptr(),
                    &mut deleted,
                    &mut updated_at,
                    &mut obj
                ),
                "index 0 of an empty list must be rejected"
            );
            assert!(obj.is_null(), "out params must be untouched when rejected");

            sia_events_free(evs);
            sia_events_free(std::ptr::null_mut());
        }
    }

    /// Same contract as sia_events_at, reported in the return value because
    /// there is no error out-param on this call either.
    #[test]
    fn key_records_at_rejects_out_of_range() {
        unsafe {
            let recs = Box::into_raw(Box::new(FfiKeyRecords(Vec::new())));
            assert_eq!(sia_key_records_len(recs), 0);

            let mut key = std::ptr::null_mut();
            let mut desc = std::ptr::null_mut();
            let mut stats = std::mem::zeroed::<KeyStatsC>();
            assert!(
                !sia_key_records_at(recs, 0, &mut key, &mut desc, &mut stats),
                "index 0 of an empty list must be rejected"
            );
            assert!(key.is_null(), "out params must be untouched when rejected");
            assert!(desc.is_null());

            sia_key_records_free(recs);
            sia_key_records_free(std::ptr::null_mut());
        }
    }

    /// Cancelling the token a blocking read is parked on must unblock it with
    /// SIA_ERR_CANCELLED, which is what makes Go context cancellation work.
    #[test]
    fn cancelled_read_returns_cancelled() {
        unsafe {
            let mock = sia_mock_new(40);
            let seed = [11u8; 32];
            let mut sdk = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_mock_sdk(
                    mock,
                    seed.as_ptr(),
                    std::ptr::null_mut(),
                    &mut sdk,
                    &mut err
                ),
                SIA_OK,
                "sia_mock_sdk: {}",
                take_err(err)
            );

            let obj = sia_object_new();
            let opts = default_upload_options();
            let mut up = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_start(sdk, obj, &opts, &mut up, &mut err),
                SIA_OK,
                "sia_upload_start: {}",
                take_err(err)
            );
            let payload = vec![5u8; 5 << 20];
            let mut err = std::ptr::null_mut();
            let mut wrote = 0usize;
            assert_eq!(
                sia_upload_write(
                    up,
                    payload.as_ptr(),
                    payload.len(),
                    std::ptr::null_mut(),
                    &mut wrote,
                    &mut err
                ),
                SIA_OK,
                "sia_upload_write: {}",
                take_err(err)
            );
            assert_eq!(
                wrote,
                payload.len(),
                "a successful write must report it all"
            );
            let mut uploaded = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_upload_finish(up, std::ptr::null_mut(), &mut uploaded, &mut err),
                SIA_OK,
                "sia_upload_finish: {}",
                take_err(err)
            );
            sia_upload_free(up);

            let dopts = default_download_options();
            let mut dl = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_start(sdk, uploaded, &dopts, &mut dl, &mut err),
                SIA_OK,
                "sia_download_start: {}",
                take_err(err)
            );

            let cancel = sia_cancel_new();
            sia_cancel_cancel(cancel);

            let mut buf = vec![0u8; 256 << 10];
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            let code = sia_download_read(dl, buf.as_mut_ptr(), buf.len(), cancel, &mut n, &mut err);
            let msg = take_err(err);
            assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");

            sia_cancel_free(cancel);
            sia_download_free(dl);
            sia_object_free(uploaded);
            sia_object_free(obj);
            sia_sdk_free(sdk);
            sia_mock_free(mock);
        }
    }
}
