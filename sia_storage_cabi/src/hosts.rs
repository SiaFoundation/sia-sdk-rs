use crate::abi::*;
use sia_storage::{GeoLocation, Host, HostQuery, Protocol, Sdk, SharedSdk};
use std::ffi::{CString, c_char};
use tokio_util::sync::CancellationToken;

/// Filters for a host listing. A zeroed struct with a null `country` applies
/// no filters, which is the whole set the indexer would return by default.
#[repr(C)]
pub(crate) struct HostQueryC {
    /// When false, `latitude` and `longitude` are ignored and hosts come back
    /// in the indexer's own order rather than sorted by proximity.
    pub(crate) has_location: bool,
    pub(crate) latitude: f64,
    pub(crate) longitude: f64,
    /// Zero for the indexer's default paging, as elsewhere in this ABI.
    pub(crate) offset: u64,
    pub(crate) limit: u64,
    /// ISO 3166-1 alpha-2, or null for no country filter.
    pub(crate) country: *const c_char,
}

/// Builds a [`HostQuery`] from the C struct, always scoped to SiaMux.
///
/// The protocol is not the caller's to choose. This library links the native
/// transport, which is SiaMux only: `web_transport` is compiled for wasm32
/// alone, and the SiaMux client skips any address on another protocol. Letting
/// a caller ask for QUIC would hand back hosts it could never dial.
///
/// # Safety
/// - `c.country` must be null or point to a NUL terminated string.
pub(crate) unsafe fn make_host_query(c: &HostQueryC) -> Result<HostQuery, String> {
    let (offset, limit) = paging(c.offset, c.limit);
    let country = if c.country.is_null() {
        None
    } else {
        match unsafe { cstr(c.country) } {
            Ok(s) => Some(s.to_string()),
            Err(e) => return Err(format!("invalid country: {e}")),
        }
    };
    Ok(HostQuery {
        location: c.has_location.then_some(GeoLocation {
            latitude: c.latitude,
            longitude: c.longitude,
        }),
        offset,
        limit,
        protocol: Some(Protocol::SiaMux),
        country,
    })
}

/// Serializes a host listing the way the indexer and the other bindings emit
/// it, so a consumer can decode straight into its own type.
fn hosts_json(err: ErrOut, hosts: Vec<Host>, out_json: *mut *mut c_char) -> i32 {
    let json = match serde_json::to_string(&hosts) {
        Ok(j) => j,
        Err(e) => return set_err(err, SIA_ERR, format!("failed to encode hosts: {e}")),
    };
    match CString::new(json) {
        Ok(s) => {
            unsafe { *out_json = s.into_raw() }
            SIA_OK
        }
        Err(e) => set_err(err, SIA_ERR, format!("failed to encode hosts: {e}")),
    }
}

/// Lists the usable hosts the indexer knows, as a JSON array.
///
/// Always scoped to SiaMux hosts, because that is the only protocol this
/// library's transport can dial.
///
/// Each element carries `publicKey`, `addresses` (each with `protocol` and
/// `address`), `countryCode`, `latitude`, `longitude` and `goodForUpload`.
/// The array is JSON rather than a typed collection because a host's address
/// list is variable length, and this shape matches what the indexer returns.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `query` must be non null and point to an initialised struct, whose `country` is null or NUL
///   terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_json` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_hosts(
    sdk: *const Sdk,
    query: *const HostQueryC,
    cancel: *mut CancellationToken,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(query)) = (unsafe { (sdk.as_ref(), query.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let query = match unsafe { make_host_query(query) } {
            Ok(q) => q,
            Err(msg) => return set_err(err, SIA_ERR, msg),
        };
        match block_on(cancel, sdk.hosts(query)) {
            None => set_cancelled(err),
            Some(Ok(hosts)) => hosts_json(err, hosts, out_json),
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// The hosts serving this sharing key's objects, in the same JSON shape as
/// [`sia_sdk_hosts`]. Scoped to the key rather than the whole indexer.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `query` must be non null and point to an initialised struct, whose `country` is null or NUL
///   terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_json` must be non null and writable. On success it receives an owned string that must be
///   released with `sia_string_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_hosts(
    sdk: *const SharedSdk,
    query: *const HostQueryC,
    cancel: *mut CancellationToken,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    let cancel = unsafe { cancel.as_ref() };
    guarded(err, || {
        let (Some(sdk), Some(query)) = (unsafe { (sdk.as_ref(), query.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let query = match unsafe { make_host_query(query) } {
            Ok(q) => q,
            Err(msg) => return set_err(err, SIA_ERR, msg),
        };
        match block_on(cancel, sdk.hosts(query)) {
            None => set_cancelled(err),
            Some(Ok(hosts)) => hosts_json(err, hosts, out_json),
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}
