use crate::abi::*;
use crate::builder::builder_error;
use crate::download::{DownloadOptionsC, FfiDownload, make_download_options, start_download};
use crate::object::write_object_array;
use crate::sharing::{KeyStatsC, key_stats_c};
use sia_storage::{Object, ObjectSummary, SharedSdk};
use std::ffi::c_char;
use tokio_util::sync::CancellationToken;

/// Connects to `indexer_url` as the recipient of the sharing key derived from
/// `seed`.
///
/// Unlike `sia_builder_connect` there is no registration or approval step: the
/// seed is the whole credential, and how it reached the recipient is the
/// caller's business. The returned handle is read only. It can list and
/// download the objects the key grants access to, and nothing else.
///
/// # Safety
/// - `indexer_url` must be non null and NUL terminated.
/// - `seed` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_shared_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_connect(
    indexer_url: *const c_char,
    seed: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut SharedSdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let url = match unsafe { cstr(&indexer_url) } {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid indexer url: {e}")),
        };
        let seed = unsafe { seed_from_ptr(seed) };
        match block_on(cancel, SharedSdk::connect(url, seed)) {
            None => set_cancelled(err),
            Some(Ok(sdk)) => {
                unsafe { *out = Box::into_raw(Box::new(sdk)) }
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

/// Like `sia_shared_sdk_connect`, but chooses the response encoding. CBOR is
/// what `sia_shared_sdk_connect` asks for; pass false for JSON. Request bodies
/// are JSON either way.
///
/// # Safety
/// - `indexer_url` must be non null and NUL terminated.
/// - `seed` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_shared_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_connect_with_cbor(
    indexer_url: *const c_char,
    seed: *const u8,
    cbor: bool,
    cancel: *mut CancellationToken,
    out: *mut *mut SharedSdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let url = match unsafe { cstr(&indexer_url) } {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid indexer url: {e}")),
        };
        let seed = unsafe { seed_from_ptr(seed) };
        match block_on(cancel, SharedSdk::connect_with_cbor(url, seed, cbor)) {
            None => set_cancelled(err),
            Some(Ok(sdk)) => {
                unsafe { *out = Box::into_raw(Box::new(sdk)) }
                SIA_OK
            }
            Some(Err(e)) => builder_error(err, e),
        }
    })
}

/// A page of object summaries, owning every summary in it.
pub(crate) struct FfiObjectSummaries(pub(crate) Vec<ObjectSummary>);

/// The fixed part of a summary. Metadata is variable length, so it is read
/// separately with `sia_object_summaries_metadata`.
#[repr(C)]
pub(crate) struct ObjectSummaryC {
    pub(crate) id: [u8; 32],
    pub(crate) size: u64,
    pub(crate) created_at_unix_us: i64,
    pub(crate) updated_at_unix_us: i64,
}

/// Lists a page of the objects the sharing key grants access to, without their
/// slabs. A summary is enough to show an object but not to download it, and is
/// a small fraction of the size, so a listing that only needs names and sizes
/// should use this rather than `sia_shared_sdk_objects`.
///
/// Pass 0 for `offset` or `limit` to take the indexer's default paging.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned collection that must be
///   released with `sia_object_summaries_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_object_summaries(
    sdk: *const SharedSdk,
    offset: u64,
    limit: u64,
    cancel: *mut CancellationToken,
    out: *mut *mut FfiObjectSummaries,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let (offset, limit) = paging(offset, limit);
        match block_on(cancel, sdk.object_summaries(offset, limit)) {
            None => set_cancelled(err),
            Some(Ok(summaries)) => {
                unsafe { *out = Box::into_raw(Box::new(FfiObjectSummaries(summaries))) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `s` may be null, which returns 0. Otherwise it must be a live collection from
///   `sia_shared_sdk_object_summaries` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_summaries_len(s: *const FfiObjectSummaries) -> usize {
    match unsafe { s.as_ref() } {
        Some(s) => s.0.len(),
        None => 0,
    }
}

/// Copies the fixed part of the summary at `i`. Returns false when `i` is out
/// of range, leaving `out` untouched.
///
/// # Safety
/// - `s` may be null, which returns false. Otherwise it must be a live collection from
///   `sia_shared_sdk_object_summaries` that has not been freed.
/// - `out` must be non null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_summaries_at(
    s: *const FfiObjectSummaries,
    i: usize,
    out: *mut ObjectSummaryC,
) -> bool {
    let Some(s) = (unsafe { s.as_ref() }) else {
        return false;
    };
    let Some(summary) = s.0.get(i) else {
        return false;
    };
    unsafe {
        *out = ObjectSummaryC {
            id: summary.id.into(),
            size: summary.size,
            created_at_unix_us: summary.created_at.timestamp_micros(),
            updated_at_unix_us: summary.updated_at.timestamp_micros(),
        }
    }
    true
}

/// Returns the metadata length of the summary at `i`, whether or not it was
/// written, so a caller can size its buffer with a null `buf` and call again.
/// An `i` out of range reports 0.
///
/// # Safety
/// - `s` may be null, which returns 0. Otherwise it must be a live collection from
///   `sia_shared_sdk_object_summaries` that has not been freed.
/// - `buf` may be null, which measures without writing. Otherwise it must be writable for `cap`
///   bytes, and nothing is written unless `cap` covers the whole metadata.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_summaries_metadata(
    s: *const FfiObjectSummaries,
    i: usize,
    buf: *mut u8,
    cap: usize,
) -> usize {
    let Some(s) = (unsafe { s.as_ref() }) else {
        return 0;
    };
    let Some(summary) = s.0.get(i) else {
        return 0;
    };
    let meta = &summary.metadata;
    if !buf.is_null() && cap >= meta.len() && !meta.is_empty() {
        unsafe { std::slice::from_raw_parts_mut(buf, meta.len()) }.copy_from_slice(meta);
    }
    meta.len()
}

/// # Safety
/// - `s` may be null. Otherwise it must come from `sia_shared_sdk_object_summaries` and must not
///   be used again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_summaries_free(s: *mut FfiObjectSummaries) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}

/// Releases a shared SDK handle.
///
/// A download started from it keeps its own token refresh alive, so freeing
/// this while one is in flight is safe and the download stays usable.
///
/// # Safety
/// - `sdk` may be null, which does nothing. Otherwise it must be a live handle from
///   `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_free(sdk: *mut SharedSdk) {
    if !sdk.is_null() {
        drop(unsafe { Box::from_raw(sdk) });
    }
}

/// Fetches the indexer's current stats for the sharing key this handle holds.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_stats` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_stats(
    sdk: *const SharedSdk,
    cancel: *mut CancellationToken,
    out_stats: *mut KeyStatsC,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.stats()) {
            None => set_cancelled(err),
            Some(Ok(stats)) => {
                unsafe { *out_stats = key_stats_c(&stats) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// Retrieves and decrypts one object the sharing key grants access to.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_object(
    sdk: *const SharedSdk,
    id: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let key = unsafe { hash_from_ptr(id) };
        match block_on(cancel, sdk.object(&key)) {
            None => set_cancelled(err),
            Some(Ok(obj)) => {
                unsafe { *out = Box::into_raw(Box::new(obj)) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// Lists and decrypts a page of the objects the sharing key grants access to.
/// Pass 0 for offset or limit to use the indexer's default paging.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_objs` must be non null and writable. On success it receives an owned array that must be
///   released with `sia_object_array_free`.
/// - `out_len` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_objects(
    sdk: *const SharedSdk,
    offset: u64,
    limit: u64,
    cancel: *mut CancellationToken,
    out_objs: *mut *mut *mut Object,
    out_len: *mut usize,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let (offset, limit) = paging(offset, limit);
        match block_on(cancel, sdk.objects(offset, limit)) {
            None => set_cancelled(err),
            Some(Ok(objects)) => {
                unsafe { write_object_array(objects, out_objs, out_len) };
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// Streams a shared object's data, paying hosts with the account tokens the
/// sharing key's owner funds. The handle is an ordinary download, read with
/// `sia_download_read` and released with `sia_download_free`.
///
/// It keeps the token refresh alive on its own, so it outlives
/// `sia_shared_sdk_free` and stays usable for transfers longer than a token's
/// five minute validity.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_object`, `sia_shared_sdk_objects` or any other call returning an object,
///   that has not been freed.
/// - `opts` must be non null and point to an initialised struct.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_download_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_download_start(
    sdk: *const SharedSdk,
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
