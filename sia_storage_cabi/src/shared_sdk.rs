use crate::abi::*;
use crate::builder::builder_error;
use crate::download::{DownloadOptionsC, FfiDownload, make_download_options, start_download};
use crate::object::write_object_array;
use crate::sharing::{KeyStatsC, key_stats_c};
use sia_storage::{Object, SharedSdk};
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
        let url = match unsafe { cstr(indexer_url) } {
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
