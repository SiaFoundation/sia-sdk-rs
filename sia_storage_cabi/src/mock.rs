use crate::abi::*;
use crate::builder::builder_error;
use sia_storage::mock::MockNetwork;
use sia_storage::{Sdk, SharedSdk};
use std::ffi::c_char;
use tokio_util::sync::CancellationToken;

pub(crate) struct FfiMock {
    pub(crate) network: MockNetwork,
    /// The keys add_hosts handed back, kept so the slow host controls can
    /// address hosts by index. MockNetwork itself does not retain them.
    pub(crate) hosts: Vec<sia_storage::PublicKey>,
}

/// # Safety
/// - This function is only callable across the C ABI and takes no pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_new(num_hosts: usize) -> *mut FfiMock {
    let network = MockNetwork::new();
    let hosts = network.add_hosts(num_hosts);
    Box::into_raw(Box::new(FfiMock { network, hosts }))
}

/// # Safety
/// - `m` may be null. Otherwise it must come from `sia_mock_new` and must not be used again after
///   this returns.
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

/// Builds a SharedSdk served by the mock network, as the recipient of the
/// sharing key derived from `seed`. The result is an ordinary handle and is
/// released with `sia_shared_sdk_free` like any other.
///
/// # Safety
/// - `m` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_mock_new` that has not been freed.
/// - `seed` must be readable for 32 bytes.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out` must be non null and writable. On success it receives an owned handle that must be
///   released with `sia_shared_sdk_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_shared_sdk(
    m: *const FfiMock,
    seed: *const u8,
    cancel: *mut CancellationToken,
    out: *mut *mut SharedSdk,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let Some(m) = (unsafe { m.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let seed = unsafe { seed_from_ptr(seed) };
        match block_on(cancel, m.network.shared_sdk(seed)) {
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_pinned_slabs(m: *const FfiMock) -> usize {
    let Some(m) = (unsafe { m.as_ref() }) else {
        return 0;
    };
    m.network.pinned_slabs()
}

/// Makes the first `n` hosts slow, each delaying every RPC by `delay_ms`.
///
/// Addressed by count rather than by key because that is how the matrix is
/// actually driven on both sides: the Rust tests take the first n of
/// `add_hosts`, and the Go engine's mock had a `SetSlowHosts(n, d)` of its
/// own. Passing an n above the host count marks every host.
///
/// Host selection behaviour is invisible to a benchmark where every host is
/// fast, so without this the degraded matrix cannot be reached from Go at all.
///
/// # Safety
/// - `m` may be null, in which case this does nothing. Otherwise it must be a live handle from
///   `sia_mock_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_set_slow_hosts(m: *const FfiMock, n: usize, delay_ms: u64) {
    let Some(m) = (unsafe { m.as_ref() }) else {
        return;
    };
    let n = n.min(m.hosts.len());
    m.network.set_slow_hosts(
        m.hosts[..n].iter().copied(),
        std::time::Duration::from_millis(delay_ms),
    );
}

/// Clears every slow host setting, returning the network to uniformly fast.
///
/// # Safety
/// - `m` may be null, in which case this does nothing. Otherwise it must be a live handle from
///   `sia_mock_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_mock_reset_slow_hosts(m: *const FfiMock) {
    let Some(m) = (unsafe { m.as_ref() }) else {
        return;
    };
    m.network.reset_slow_hosts();
}
