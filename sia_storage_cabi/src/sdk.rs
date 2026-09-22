use crate::abi::*;
use crate::object::{FfiEvent, FfiEvents};
use sia_storage::{Object, ObjectsCursor, Sdk};
use std::ffi::{CString, c_char};
use tokio_util::sync::CancellationToken;

/// # Safety
/// - `sdk` may be null. Otherwise it must come from `sia_builder_connect`, `sia_builder_register`
///   or `sia_mock_sdk` and must not be used again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_free(sdk: *mut Sdk) {
    if !sdk.is_null() {
        drop(unsafe { Box::from_raw(sdk) });
    }
}

/// # Safety
/// - `sdk` may be null, which does nothing. Otherwise it must be a live handle from
///   `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `out` must be writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_app_key(sdk: *const Sdk, out: *mut u8) {
    let Some(sdk) = (unsafe { sdk.as_ref() }) else {
        return;
    };
    let seed = sdk.app_key().export();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&seed);
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_json` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_account(
    sdk: *const Sdk,
    cancel: *mut CancellationToken,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.account()) {
            None => set_cancelled(err),
            Some(Ok(account)) => match serde_json::to_string(&account) {
                Ok(js) => {
                    unsafe { *out_json = CString::new(js).unwrap_or_default().into_raw() }
                    SIA_OK
                }
                Err(e) => set_typed_err(err, &e),
            },
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object(
    sdk: *const Sdk,
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

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `after_id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_events_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
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
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let cursor = if has_cursor {
            let after = match sia_storage::DateTime::from_timestamp_micros(after_unix_us) {
                Some(t) => t,
                None => return set_err(err, SIA_ERR, "invalid cursor timestamp"),
            };
            Some(ObjectsCursor {
                after,
                id: unsafe { hash_from_ptr(after_id) },
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
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_pin_object(
    sdk: *const Sdk,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(obj)) = (unsafe { (sdk.as_ref(), obj.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.pin_object(obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_update_object_metadata(
    sdk: *const Sdk,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(obj)) = (unsafe { (sdk.as_ref(), obj.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.update_object_metadata(obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_delete_object(
    sdk: *const Sdk,
    id: *const u8,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let key = unsafe { hash_from_ptr(id) };
        match block_on(cancel, sdk.delete_object(&key)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_prune_slabs(
    sdk: *const Sdk,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.prune_slabs()) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `out_url` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object_share_url(
    sdk: *const Sdk,
    obj: *const Object,
    valid_until_unix_us: i64,
    out_url: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let (Some(sdk), Some(obj)) = (unsafe { (sdk.as_ref(), obj.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
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
            Err(e) => set_typed_err(err, &e),
        }
    })
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `share_url` must be non null and NUL terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_object_from_share_url(
    sdk: *const Sdk,
    share_url: *const c_char,
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
        let url = match unsafe { cstr(share_url) } {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid share url: {e}")),
        };
        match block_on(cancel, sdk.object_from_share_url(url)) {
            None => set_cancelled(err),
            Some(Ok(obj)) => {
                unsafe { *out = Box::into_raw(Box::new(obj)) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// Retrieves a pinned slab from the indexer by its id, as a JSON object.
///
/// It carries `version`, `id`, `encryptionKey`, `minShards` and `sectors`,
/// each sector with its `root` and `hostKey`. JSON rather than a typed struct
/// because the sector list is variable length, the same reason
/// `sia_sdk_hosts` returns JSON.
///
/// The `encryptionKey` is the slab's data key. Treat the result as secret:
/// anyone holding it and the sector roots can recover the slab's contents.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_json` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_slab(
    sdk: *const Sdk,
    id: *const u8,
    cancel: *mut CancellationToken,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let id = unsafe { hash_from_ptr(id) };
        match block_on(cancel, sdk.slab(&id)) {
            None => set_cancelled(err),
            Some(Ok(slab)) => {
                let json = match serde_json::to_string(&slab) {
                    Ok(j) => j,
                    Err(e) => return set_err(err, SIA_ERR, format!("failed to encode slab: {e}")),
                };
                match CString::new(json) {
                    Ok(s) => {
                        unsafe { *out_json = s.into_raw() }
                        SIA_OK
                    }
                    Err(e) => set_err(err, SIA_ERR, format!("failed to encode slab: {e}")),
                }
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}
