use crate::abi::*;
use crate::object::write_object_array;
use sia_storage::{KeyRecord, KeyStats, Object, Sdk, SharingError, SharingKey, SharingKeyOptions};
use std::ffi::{CString, c_char};
use tokio_util::sync::CancellationToken;

pub(crate) struct FfiKeyRecords(pub(crate) Vec<KeyRecord>);

/// The indexer's snapshot of what a sharing key grants access to. Every field
/// is fixed width so the whole record crosses in one read rather than one call
/// per field.
#[repr(C)]
pub(crate) struct KeyStatsC {
    pub(crate) object_count: u64,
    pub(crate) object_size: u64,
    pub(crate) pinned_data: u64,
    pub(crate) pinned_size: u64,
    pub(crate) created_at_unix_us: i64,
    /// False when the key never expires, in which case `expires_at` is 0.
    pub(crate) has_expiry: bool,
    pub(crate) expires_at_unix_us: i64,
}

/// Maps the sharing errors a caller can act on to their own status codes, so Go
/// can match them with errors.Is rather than on message text. Everything else
/// keeps its message under `SIA_ERR`.
pub(crate) fn sharing_error(err: ErrOut, e: SharingError) -> i32 {
    let code = match &e {
        SharingError::ObjectNotAttached => SIA_ERR_OBJECT_NOT_ATTACHED,
        SharingError::KeyMismatch => SIA_ERR_KEY_MISMATCH,
        _ => SIA_ERR,
    };
    set_err(err, code, e.to_string())
}

pub(crate) fn key_stats_c(s: &KeyStats) -> KeyStatsC {
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

/// Rebuilds a sharing key from an exported seed. This is how a recipient, or a
/// process that persisted the seed, gets a usable credential back.
///
/// # Safety
/// - `seed` must be readable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_import(seed: *const u8) -> *mut SharingKey {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(unsafe { std::slice::from_raw_parts(seed, 32) });
    Box::into_raw(Box::new(SharingKey::import(buf)))
}

/// # Safety
/// - `key` may be null. Otherwise it must come from `sia_sharing_key_import` or
///   `sia_sdk_create_sharing_key` and must not be used again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_free(key: *mut SharingKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Writes the key's 32-byte seed, which is the entire credential. Treat the
/// output as secret.
///
/// # Safety
/// - `key` may be null, which does nothing. Otherwise it must be a live handle from
///   `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `out` must be writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_export(key: *const SharingKey, out: *mut u8) {
    let Some(key) = (unsafe { key.as_ref() }) else {
        return;
    };
    let seed = key.export();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&seed);
}

/// Writes the key's public half, by which the indexer identifies it. Safe to
/// log or display.
///
/// # Safety
/// - `key` may be null, which does nothing. Otherwise it must be a live handle from
///   `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `out` must be writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sharing_key_public_key(key: *const SharingKey, out: *mut u8) {
    let Some(key) = (unsafe { key.as_ref() }) else {
        return;
    };
    let pk = key.public_key();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(pk.as_ref());
}

/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `description` must be non null and NUL terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_sharing_key_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
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
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let description = match unsafe { cstr(description) } {
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

/// Fetches the indexer's current record for one key. *`out_description` receives
/// an owned string; free it with `sia_string_free`.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_description` must be non null and writable. On success it receives an owned string that
///   must be released with `sia_string_free`.
/// - `out_stats` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_sharing_key(
    sdk: *const Sdk,
    key: *const SharingKey,
    cancel: *mut CancellationToken,
    out_description: *mut *mut c_char,
    out_stats: *mut KeyStatsC,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(key)) = (unsafe { (sdk.as_ref(), key.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
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
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_key_records_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_sharing_keys(
    sdk: *const Sdk,
    offset: u64,
    limit: u64,
    cancel: *mut CancellationToken,
    out: *mut *mut FfiKeyRecords,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
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

/// # Safety
/// - `recs` may be null, which returns 0. Otherwise it must be a live handle from
///   `sia_sdk_sharing_keys` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_len(recs: *const FfiKeyRecords) -> usize {
    let Some(recs) = (unsafe { recs.as_ref() }) else {
        return 0;
    };
    recs.0.len()
}

/// Copies the record at `i` out. *`out_key` receives an owned key handle, freed
/// with `sia_sharing_key_free`, and *`out_description` an owned string, freed with
/// `sia_string_free`. Returns false when `i` is out of range, leaving the out
/// params untouched.
///
/// # Safety
/// - `recs` may be null, which returns false. Otherwise it must be a live handle from
///   `sia_sdk_sharing_keys` that has not been freed.
/// - `out_key` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_sharing_key_free`.
/// - `out_description` must be non null and writable. On success it receives an owned string that
///   must be released with `sia_string_free`.
/// - `out_stats` must be non null and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_at(
    recs: *const FfiKeyRecords,
    i: usize,
    out_key: *mut *mut SharingKey,
    out_description: *mut *mut c_char,
    out_stats: *mut KeyStatsC,
) -> bool {
    let Some(recs) = (unsafe { recs.as_ref() }) else {
        return false;
    };
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

/// # Safety
/// - `recs` may be null. Otherwise it must come from `sia_sdk_sharing_keys` and must not be used
///   again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_key_records_free(recs: *mut FfiKeyRecords) {
    if !recs.is_null() {
        drop(unsafe { Box::from_raw(recs) });
    }
}

/// Attaches an object to a sharing key, re-sealing its keys under that key.
/// Attaching an object already attached replaces its sealed keys, so a failed
/// call can be retried with the same object.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_share_object(
    sdk: *const Sdk,
    key: *const SharingKey,
    obj: *const Object,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(key), Some(obj)) =
            (unsafe { (sdk.as_ref(), key.as_ref(), obj.as_ref()) })
        else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.share_object(key, obj)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Lists and decrypts the objects attached to a key. *`out_objs` receives a heap
/// array of owned handles; free the array with `sia_object_array_free`. Pass 0
/// for offset or limit to use the indexer's default paging.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_objs` must be non null and writable. On success it receives an owned array that must be
///   released with `sia_object_array_free`.
/// - `out_len` must be non null and writable.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
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
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(key)) = (unsafe { (sdk.as_ref(), key.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let (offset, limit) = paging(offset, limit);
        match block_on(cancel, sdk.shared_objects(key, offset, limit)) {
            None => set_cancelled(err),
            Some(Ok(objects)) => {
                unsafe { write_object_array(objects, out_objs, out_len) };
                SIA_OK
            }
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Detaches one object from a key. Returns `SIA_ERR_OBJECT_NOT_ATTACHED` when the
/// object was not attached to it.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `object_id` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_unshare_object(
    sdk: *const Sdk,
    key: *const SharingKey,
    object_id: *const u8,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(key)) = (unsafe { (sdk.as_ref(), key.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let id = unsafe { hash_from_ptr(object_id) };
        match block_on(cancel, sdk.unshare_object(key, &id)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}

/// Revokes a key, detaching every object attached to it at once. Downloads
/// already in flight can keep reading from hosts for up to five more minutes.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_sharing_key_import` or `sia_sdk_create_sharing_key` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_revoke_sharing_key(
    sdk: *const Sdk,
    key: *const SharingKey,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(key)) = (unsafe { (sdk.as_ref(), key.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        match block_on(cancel, sdk.revoke_sharing_key(key)) {
            None => set_cancelled(err),
            Some(Ok(())) => SIA_OK,
            Some(Err(e)) => sharing_error(err, e),
        }
    })
}
