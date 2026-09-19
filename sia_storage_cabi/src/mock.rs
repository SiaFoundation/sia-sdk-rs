use crate::abi::*;
use crate::builder::builder_error;
use sia_storage::Sdk;
#[cfg(feature = "mock")]
use sia_storage::mock::MockNetwork;
use std::ffi::c_char;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "mock")]
pub(crate) struct FfiMock {
    pub(crate) network: MockNetwork,
}

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_new(num_hosts: usize) -> *mut FfiMock {
    let network = MockNetwork::new();
    network.add_hosts(num_hosts);
    Box::into_raw(Box::new(FfiMock { network }))
}

/// # Safety
/// - `m` may be null. Otherwise it must come from `sia_mock_new` and must not be used again after
///   this returns.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_free(m: *mut FfiMock) {
    if !m.is_null() {
        drop(unsafe { Box::from_raw(m) });
    }
}

/// Builds an Sdk served by the mock network. The result is an ordinary handle
/// and is released with `sia_sdk_free` like any other.
///
/// # Safety
/// - `m` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_mock_new` that has not been freed.
/// - `app_key` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_sdk(
    m: *const FfiMock,
    app_key: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut Sdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(m) = (unsafe { m.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let key = unsafe { app_key_from_ptr(app_key) };
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
///
/// # Safety
/// - `m` may be null, which does nothing. Otherwise it must be a live handle from `sia_mock_new`
///   that has not been freed.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_clear_sectors(m: *const FfiMock) {
    let Some(m) = (unsafe { m.as_ref() }) else {
        return;
    };
    m.network.clear_sectors();
}

/// # Safety
/// - `m` may be null, which returns 0. Otherwise it must be a live handle from `sia_mock_new` that
///   has not been freed.
#[cfg(feature = "mock")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_pinned_slabs(m: *const FfiMock) -> usize {
    let Some(m) = (unsafe { m.as_ref() }) else {
        return 0;
    };
    m.network.pinned_slabs()
}
