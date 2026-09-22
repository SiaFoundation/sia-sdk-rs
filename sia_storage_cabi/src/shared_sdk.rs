use crate::abi::*;
use crate::builder::builder_error;
use sia_storage::SharedSdk;
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
