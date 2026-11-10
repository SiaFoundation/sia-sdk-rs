use crate::abi::*;
use sia_core::types::v2::NetAddress;
use sia_storage::{GeoLocation, Host, HostQuery, Protocol, Sdk, SharedSdk};
use std::ffi::c_char;
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
        match unsafe { cstr(&c.country) } {
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

/// A host address that speaks SiaMux.
pub const SIA_PROTOCOL_SIAMUX: u8 = 0;

/// A host address that speaks QUIC.
pub const SIA_PROTOCOL_QUIC: u8 = 1;

/// One way to reach a host. `address` is owned by the array it came from.
#[repr(C)]
pub(crate) struct NetAddressC {
    /// `SIA_PROTOCOL_SIAMUX` or `SIA_PROTOCOL_QUIC`.
    pub(crate) protocol: u8,
    /// `host:port`.
    pub(crate) address: *const c_char,
}

impl From<NetAddress> for NetAddressC {
    fn from(a: NetAddress) -> Self {
        NetAddressC {
            protocol: match a.protocol {
                Protocol::SiaMux => SIA_PROTOCOL_SIAMUX,
                Protocol::QUIC => SIA_PROTOCOL_QUIC,
            },
            address: lossy_cstring(a.address).into_raw(),
        }
    }
}

impl Drop for NetAddressC {
    fn drop(&mut self) {
        unsafe { sia_string_free(self.address.cast_mut()) }
    }
}

/// A storage host. Every pointer in it is owned by the array it came from and
/// is valid until that array is freed with `sia_host_array_free`.
#[repr(C)]
pub(crate) struct HostC {
    pub(crate) public_key: [u8; 32],
    /// Null when `addresses_len` is 0.
    pub(crate) addresses: *const NetAddressC,
    pub(crate) addresses_len: usize,
    /// ISO 3166-1 alpha-2.
    pub(crate) country_code: *const c_char,
    pub(crate) latitude: f64,
    pub(crate) longitude: f64,
    pub(crate) good_for_upload: bool,
}

impl From<Host> for HostC {
    fn from(h: Host) -> Self {
        let addresses: Vec<NetAddressC> = h.addresses.into_iter().map(Into::into).collect();
        let (addresses, addresses_len) = into_raw_array(addresses);
        HostC {
            public_key: h.public_key.into(),
            addresses,
            addresses_len,
            country_code: lossy_cstring(h.country_code).into_raw(),
            latitude: h.latitude,
            longitude: h.longitude,
            good_for_upload: h.good_for_upload,
        }
    }
}

impl Drop for HostC {
    fn drop(&mut self) {
        unsafe {
            free_raw_array(self.addresses.cast_mut(), self.addresses_len);
            sia_string_free(self.country_code.cast_mut());
        }
    }
}

/// # Safety
/// - `out_hosts` and `out_len` must be non null and writable.
unsafe fn write_hosts(hosts: Vec<Host>, out_hosts: *mut *mut HostC, out_len: *mut usize) {
    let hosts: Vec<HostC> = hosts.into_iter().map(Into::into).collect();
    let (ptr, len) = into_raw_array(hosts);
    unsafe {
        *out_hosts = ptr;
        *out_len = len;
    }
}

/// Lists the usable hosts the indexer knows.
///
/// Always scoped to SiaMux hosts, because that is the only protocol this
/// library's transport can dial.
///
/// An empty listing sets `*out_hosts` to null and `*out_len` to 0.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_builder_connect`, `sia_builder_register` or `sia_mock_sdk` that has not been freed.
/// - `query` must be non null and point to an initialised struct, whose `country` is null or NUL
///   terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_hosts` and `out_len` must be non null and writable. On success they receive an owned
///   array that must be released with `sia_host_array_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_sdk_hosts(
    sdk: *const Sdk,
    query: *const HostQueryC,
    cancel: *mut CancellationToken,
    out_hosts: *mut *mut HostC,
    out_len: *mut usize,
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
            Some(Ok(hosts)) => {
                unsafe { write_hosts(hosts, out_hosts, out_len) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// The hosts serving this sharing key's objects, read the same way as
/// [`sia_sdk_hosts`]. Scoped to the key rather than the whole indexer.
///
/// # Safety
/// - `sdk` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live handle
///   from `sia_shared_sdk_connect` or `sia_mock_shared_sdk` that has not been freed.
/// - `query` must be non null and point to an initialised struct, whose `country` is null or NUL
///   terminated.
/// - `cancel` may be null, which makes the call uncancellable. Otherwise it must be a live token
///   from `sia_cancel_new`.
/// - `out_hosts` and `out_len` must be non null and writable. On success they receive an owned
///   array that must be released with `sia_host_array_free`.
/// - `err` may be null. Otherwise it receives an owned message on failure that must be released
///   with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_shared_sdk_hosts(
    sdk: *const SharedSdk,
    query: *const HostQueryC,
    cancel: *mut CancellationToken,
    out_hosts: *mut *mut HostC,
    out_len: *mut usize,
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
            Some(Ok(hosts)) => {
                unsafe { write_hosts(hosts, out_hosts, out_len) }
                SIA_OK
            }
            Some(Err(e)) => set_typed_err(err, &e),
        }
    })
}

/// Releases a host array along with every address and string it points to.
///
/// # Safety
/// - `hosts` may be null, which does nothing. Otherwise it must be an unmodified array of `len`
///   hosts from `sia_sdk_hosts` or `sia_shared_sdk_hosts`, and must not be used again after this
///   returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_host_array_free(hosts: *mut HostC, len: usize) {
    unsafe { free_raw_array(hosts, len) }
}
