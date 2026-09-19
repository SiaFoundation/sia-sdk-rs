use crate::abi::*;
use sia_storage::{
    AppApiError, AppMetadata, ApprovedState, Builder, BuilderError, DisconnectedState, Hash256,
    RequestingApprovalState, Sdk,
};
use std::ffi::{CString, c_char};
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(crate) enum BuilderState {
    Disconnected(Builder<DisconnectedState>),
    Requesting(Builder<RequestingApprovalState>),
    Approved(Builder<ApprovedState>),
    Consumed,
}

pub(crate) struct FfiBuilder(pub(crate) Mutex<BuilderState>);

#[derive(serde::Deserialize)]
pub(crate) struct AppMetadataIn {
    #[serde(rename = "appID")]
    pub(crate) id: Hash256,
    pub(crate) name: String,
    pub(crate) description: String,
    #[serde(rename = "serviceURL")]
    pub(crate) service_url: String,
    #[serde(rename = "logoURL")]
    pub(crate) logo_url: Option<String>,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

pub(crate) fn builder_error(err: ErrOut, e: BuilderError) -> i32 {
    let code = match &e {
        BuilderError::RequestExpired => SIA_ERR_REQUEST_EXPIRED,
        BuilderError::Client(AppApiError::UserRejected) => SIA_ERR_USER_REJECTED,
        _ => SIA_ERR,
    };
    set_err(err, code, e.to_string())
}

/// # Safety
/// - `indexer_url` must be non null and NUL terminated.
/// - `app_meta_json` must be non null and NUL terminated.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_builder_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_new(
    indexer_url: *const c_char,
    app_meta_json: *const c_char,
    out: *mut *mut FfiBuilder,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let url = match unsafe { cstr(indexer_url) } {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid indexer url: {e}")),
        };
        let meta_json = match unsafe { cstr(app_meta_json) } {
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

/// # Safety
/// - `b` may be null. Otherwise it must come from `sia_builder_new` and must not be used again
///   after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_free(b: *mut FfiBuilder) {
    if !b.is_null() {
        drop(unsafe { Box::from_raw(b) });
    }
}

/// # Safety
/// - `b` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_new` that has not been freed.
/// - `app_key` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_connect(
    b: *mut FfiBuilder,
    app_key: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(b) = (unsafe { b.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let state = b.0.lock().unwrap();
        let builder = match &*state {
            BuilderState::Disconnected(builder) => builder,
            _ => return set_err(err, SIA_ERR_INVALID_STATE, "builder is not disconnected"),
        };
        let key = unsafe { app_key_from_ptr(app_key) };
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

/// # Safety
/// - `b` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_new` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `response_url` must be non null and writable. On success it receives an owned string that must
///   be released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_request_connection(
    b: *mut FfiBuilder,
    cancel: *mut CancellationToken,
    response_url: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(b) = (unsafe { b.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let mut state = b.0.lock().unwrap();
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

/// # Safety
/// - `b` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_new` that has not been freed.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_wait_for_approval(
    b: *mut FfiBuilder,
    cancel: *mut CancellationToken,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(b) = (unsafe { b.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let mut state = b.0.lock().unwrap();
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

/// # Safety
/// - `b` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_new` that has not been freed.
/// - `mnemonic` must be non null and NUL terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_builder_register(
    b: *mut FfiBuilder,
    mnemonic: *const c_char,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(b) = (unsafe { b.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let phrase = match unsafe { cstr(mnemonic) } {
            Ok(s) => s,
            Err(e) => return set_err(err, SIA_ERR, format!("invalid mnemonic: {e}")),
        };
        let mut state = b.0.lock().unwrap();
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
