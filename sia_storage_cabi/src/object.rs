use crate::abi::*;
use sia_storage::{Object, Sdk, SealedObject};
use std::ffi::{CString, c_char};

pub(crate) struct FfiEvent {
    pub(crate) id: [u8; 32],
    pub(crate) deleted: bool,
    pub(crate) updated_at_us: i64,
    pub(crate) object: Option<Box<Object>>,
}

pub(crate) struct FfiEvents(pub(crate) Vec<FfiEvent>);

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_new() -> *mut Object {
    Box::into_raw(Box::new(Object::default()))
}

/// Returns a copy of `o` shortened to `length` bytes.
///
/// The last retained slab is shortened to end at `length` and any slab past it
/// is dropped. A `length` at or above the object's current size copies it
/// unchanged. The original is untouched, so the caller frees both.
///
/// This only rewrites the object's slab list. The result has to be pinned with
/// `sia_sdk_pin_object` before the indexer knows about it, and the sectors the
/// dropped slabs referenced stay where they are until they are pruned.
///
/// # Safety
/// - `o` may be null, which returns null. Otherwise it must be a live handle from
///   `sia_object_new` or any call that returns an object, that has not been freed.
/// - The result is an owned handle that must be released with `sia_object_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_truncate(o: *const Object, length: u64) -> *mut Object {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(o.truncate(length)))
}

/// # Safety
/// - `o` may be null. Otherwise it must come from `sia_object_new` or any call that returns an
///   object and must not be used again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_free(o: *mut Object) {
    if !o.is_null() {
        drop(unsafe { Box::from_raw(o) });
    }
}

/// # Safety
/// - `o` may be null, which does nothing. Otherwise it must be a live handle from `sia_object_new`
///   or any call that returns an object that has not been freed.
/// - `out` must be writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_id(o: *const Object, out: *mut u8) {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return;
    };
    let id = o.id();
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(id.as_ref());
}

/// # Safety
/// - `o` may be null, which returns 0. Otherwise it must be a live handle from `sia_object_new` or
///   any call that returns an object that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_size(o: *const Object) -> u64 {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return 0;
    };
    o.size()
}

/// # Safety
/// - `o` may be null, which returns 0. Otherwise it must be a live handle from `sia_object_new` or
///   any call that returns an object that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_encoded_size(o: *const Object) -> u64 {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return 0;
    };
    o.encoded_size()
}

/// # Safety
/// - `o` may be null, which returns 0. Otherwise it must be a live handle from `sia_object_new` or
///   any call that returns an object that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_created_at(o: *const Object) -> i64 {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return 0;
    };
    o.created_at.timestamp_micros()
}

/// # Safety
/// - `o` may be null, which returns 0. Otherwise it must be a live handle from `sia_object_new` or
///   any call that returns an object that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_updated_at(o: *const Object) -> i64 {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return 0;
    };
    o.updated_at.timestamp_micros()
}

/// # Safety
/// - `o` may be null, which returns 0. Otherwise it must be a live handle from `sia_object_new` or
///   any call that returns an object that has not been freed.
/// - `buf` must be writable for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_metadata(o: *const Object, buf: *mut u8, cap: usize) -> usize {
    let Some(o) = (unsafe { o.as_ref() }) else {
        return 0;
    };
    let meta = &o.metadata;
    if !buf.is_null() && cap >= meta.len() {
        unsafe { std::slice::from_raw_parts_mut(buf, meta.len()) }.copy_from_slice(meta);
    }
    meta.len()
}

/// # Safety
/// - `o` may be null, which does nothing. Otherwise it must be a live handle from `sia_object_new`
///   or any call that returns an object that has not been freed.
/// - `data` must be readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_set_metadata(o: *mut Object, data: *const u8, len: usize) {
    let meta = if data.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let Some(o) = (unsafe { o.as_mut() }) else {
        return;
    };
    o.metadata = meta;
}

/// # Safety
/// - `evs` may be null, which returns 0. Otherwise it must be a live handle from
///   `sia_sdk_object_events` that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_events_len(evs: *const FfiEvents) -> usize {
    let Some(evs) = (unsafe { evs.as_ref() }) else {
        return 0;
    };
    evs.0.len()
}

/// # Safety
/// - `evs` may be null, which returns false. Otherwise it must be a live handle from
///   `sia_sdk_object_events` that has not been freed.
/// - `id_out` must be writable for 32 bytes.
/// - `deleted` must be non null and writable.
/// - `updated_at_unix_us` must be non null and writable.
/// - `obj` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
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
    let Some(evs) = (unsafe { evs.as_mut() }) else {
        return false;
    };
    let Some(ev) = evs.0.get_mut(i) else {
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

/// # Safety
/// - `evs` may be null. Otherwise it must come from `sia_sdk_object_events` and must not be used
///   again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_events_free(evs: *mut FfiEvents) {
    if !evs.is_null() {
        drop(unsafe { Box::from_raw(evs) });
    }
}

/// # Safety
/// - `objs` may be null. Otherwise it must be an array of `len` objects from a call that produced
///   one, and must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_array_free(objs: *mut *mut Object, len: usize) {
    if !objs.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(objs, len)) });
    }
}

/// Seals an object under the account's app key and encodes it as JSON.
/// Free the result with `sia_string_free`.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `obj` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_object_new` or any call that returns an object that has not been freed.
/// - `out_json` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_seal_json(
    sdk: *const Sdk,
    obj: *const Object,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let (Some(sdk), Some(obj)) = (unsafe { (sdk.as_ref(), obj.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
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
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `json` must be non null and NUL terminated.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_object_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_object_from_sealed_json(
    sdk: *const Sdk,
    json: *const c_char,
    out: *mut *mut Object,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let Some(sdk) = (unsafe { sdk.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let s = match unsafe { cstr(json) } {
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
            Err(e) => set_typed_err(err, &e),
        }
    })
}

/// Hands a vector of objects out as a heap array of owned handles, the shape
/// `sia_object_array_free` expects.
/// # Safety
/// - `out_objs` and `out_len` must be non null and writable. `out_objs` receives an owned array,
///   released with `sia_object_array_free`.
pub(crate) unsafe fn write_object_array(
    objects: Vec<Object>,
    out_objs: *mut *mut *mut Object,
    out_len: *mut usize,
) {
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
