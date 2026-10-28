use crate::abi::*;
use sia_storage::preauthorized_keys::{PreAuthorizedKey, PreAuthorizedKeyRequest};
use std::ffi::c_char;

#[repr(C)]
pub(crate) struct PreAuthorizedKeyRequestC {
    pub(crate) connect_key: *const c_char,
    /// Microseconds since the Unix epoch.
    pub(crate) expiration_unix_us: i64,
    pub(crate) total_uses: u32,
    /// Null for any application, otherwise a pointer to the 32-byte app ID.
    pub(crate) allowed_app_id: *const u8,
}

/// Creates a random pre-authorized key.
///
/// # Safety
/// - Free the returned handle with `sia_pre_authorized_key_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_new() -> *mut PreAuthorizedKey {
    Box::into_raw(Box::new(PreAuthorizedKey::new()))
}

/// Imports a pre-authorized key from its 32-byte seed.
///
/// # Safety
/// - `seed` may be null, which returns null. Otherwise it must be readable for 32 bytes.
/// - Free the returned handle with `sia_pre_authorized_key_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_import(seed: *const u8) -> *mut PreAuthorizedKey {
    if seed.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(PreAuthorizedKey::import(unsafe {
        seed_from_ptr(seed)
    })))
}

/// Frees a pre-authorized key handle.
///
/// # Safety
/// - `key` may be null. Otherwise it must be a live pre-authorized key handle and must not be
///   used again after this returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_free(key: *mut PreAuthorizedKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Writes the pre-authorized key's 32-byte secret seed.
///
/// # Safety
/// - `key` may be null, which does nothing. Otherwise it must be a live pre-authorized key handle.
/// - `out` must be writable for the 32-byte secret seed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_export(key: *const PreAuthorizedKey, out: *mut u8) {
    let Some(key) = (unsafe { key.as_ref() }) else {
        return;
    };
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&key.export());
}

/// Writes the pre-authorized key's 32-byte public key.
///
/// # Safety
/// - `key` may be null, which does nothing. Otherwise it must be a live pre-authorized key handle.
/// - `out` must be writable for the 32-byte public key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_public_key(
    key: *const PreAuthorizedKey,
    out: *mut u8,
) {
    let Some(key) = (unsafe { key.as_ref() }) else {
        return;
    };
    unsafe { std::slice::from_raw_parts_mut(out, 32) }.copy_from_slice(key.public_key().as_ref());
}

/// Signs a message and writes its 64-byte signature.
///
/// # Safety
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live
///   pre-authorized key handle.
/// - `message` must be readable for `message_len` bytes; it may be null when the length is zero.
/// - `out` must be writable for the 64-byte signature.
/// - `err` may be null. Otherwise, free its value on failure with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_sign(
    key: *const PreAuthorizedKey,
    message: *const u8,
    message_len: usize,
    out: *mut u8,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let Some(key) = (unsafe { key.as_ref() }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        let message = if message_len == 0 {
            &[]
        } else if message.is_null() {
            return set_err(err, SIA_ERR, "message is null with nonzero length");
        } else {
            unsafe { std::slice::from_raw_parts(message, message_len) }
        };
        let signature = key.sign(message);
        unsafe { std::slice::from_raw_parts_mut(out, 64) }.copy_from_slice(signature.as_ref());
        SIA_OK
    })
}

/// Verifies a 64-byte signature against a message and the pre-authorized key.
///
/// # Safety
/// - `key` may be null, which returns false. Otherwise it must be a live pre-authorized key handle.
/// - `message` must be readable for `message_len` bytes; it may be null when the length is zero.
/// - `signature` must be readable for 64 bytes when non null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_verify_signature(
    key: *const PreAuthorizedKey,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> bool {
    let Some(key) = (unsafe { key.as_ref() }) else {
        return false;
    };
    if signature.is_null() || (message.is_null() && message_len != 0) {
        return false;
    }
    let message = if message_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(message, message_len) }
    };
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(unsafe { std::slice::from_raw_parts(signature, 64) });
    key.public_key()
        .verify(message, &sia_storage::Signature::from(bytes))
}

/// Returns the signed pre-authorized key registration request as JSON.
///
/// # Safety
/// - `key` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must be a live
///   pre-authorized key handle.
/// - `request` may be null, which returns `SIA_ERR_INVALID_HANDLE`. Otherwise it must point to
///   an initialized struct whose `connect_key` is NUL terminated when non null and whose
///   `allowed_app_id` is null or readable for 32 bytes.
/// - `out_json` must be non null and writable. On success, free its value with `sia_string_free`.
/// - `err` may be null. Otherwise, free its value on failure with `sia_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sia_pre_authorized_key_sign_request_json(
    key: *const PreAuthorizedKey,
    request: *const PreAuthorizedKeyRequestC,
    out_json: *mut *mut c_char,
    err: *mut *mut c_char,
) -> i32 {
    let err = unsafe { ErrOut::new(err) };
    guarded(err, || {
        let (Some(key), Some(request)) = (unsafe { (key.as_ref(), request.as_ref()) }) else {
            return SIA_ERR_INVALID_HANDLE;
        };
        if request.connect_key.is_null() {
            return set_err(err, SIA_ERR, "connect key is null");
        }
        let connect_key = match unsafe { cstr(&request.connect_key) } {
            Ok(s) => s.to_string(),
            Err(e) => return set_err(err, SIA_ERR, format!("invalid connect key: {e}")),
        };
        let expiration =
            match sia_storage::DateTime::from_timestamp_micros(request.expiration_unix_us) {
                Some(t) => t,
                None => return set_err(err, SIA_ERR, "invalid expiration timestamp"),
            };
        let allowed_app_id = if request.allowed_app_id.is_null() {
            None
        } else {
            Some(unsafe { hash_from_ptr(request.allowed_app_id) })
        };
        let signed = key.sign_request(PreAuthorizedKeyRequest {
            connect_key,
            expiration,
            total_uses: request.total_uses,
            allowed_app_id,
        });
        match serde_json::to_string(&signed) {
            Ok(json) => {
                unsafe { *out_json = lossy_cstring(json).into_raw() }
                SIA_OK
            }
            Err(e) => set_err(
                err,
                SIA_ERR,
                format!("failed to encode signed request: {e}"),
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn pre_authorized_key_lifecycle() {
        unsafe {
            let key = sia_pre_authorized_key_new();
            assert!(!key.is_null());
            let mut seed = [0u8; 32];
            sia_pre_authorized_key_export(key, seed.as_mut_ptr());
            let imported = sia_pre_authorized_key_import(seed.as_ptr());
            let mut public_key = [0u8; 32];
            let mut imported_public_key = [0u8; 32];
            sia_pre_authorized_key_public_key(key, public_key.as_mut_ptr());
            sia_pre_authorized_key_public_key(imported, imported_public_key.as_mut_ptr());
            assert_eq!(public_key, imported_public_key);
            let mut signature = [0u8; 64];
            assert_eq!(
                sia_pre_authorized_key_sign(
                    key,
                    b"hello".as_ptr(),
                    5,
                    signature.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                SIA_OK
            );
            assert!(sia_pre_authorized_key_verify_signature(
                imported,
                b"hello".as_ptr(),
                5,
                signature.as_ptr()
            ));
            assert!(!sia_pre_authorized_key_verify_signature(
                imported,
                b"wrong".as_ptr(),
                5,
                signature.as_ptr()
            ));
            assert_eq!(
                sia_pre_authorized_key_sign(
                    key,
                    std::ptr::null(),
                    0,
                    signature.as_mut_ptr(),
                    std::ptr::null_mut()
                ),
                SIA_OK
            );
            assert!(sia_pre_authorized_key_verify_signature(
                imported,
                std::ptr::null(),
                0,
                signature.as_ptr()
            ));
            sia_pre_authorized_key_free(key);
            sia_pre_authorized_key_free(imported);
            sia_pre_authorized_key_free(std::ptr::null_mut());
            assert!(sia_pre_authorized_key_import(std::ptr::null()).is_null());
        }
    }

    #[test]
    fn pre_authorized_key_sign_request_converts_c_arguments() {
        unsafe {
            let key = sia_pre_authorized_key_import([2u8; 32].as_ptr());
            let core_key = PreAuthorizedKey::import([2u8; 32]);
            let app_id = [3u8; 32];
            for (expiration_unix_us, seconds, nanos, allowed_app_id, expected_app_id) in [
                (
                    183_123_456,
                    183,
                    123_456_000,
                    app_id.as_ptr(),
                    Some(sia_storage::Hash256::new(app_id)),
                ),
                (-500_000, -1, 500_000_000, std::ptr::null(), None),
            ] {
                let mut out = std::ptr::null_mut();
                let mut err = std::ptr::null_mut();
                let request = PreAuthorizedKeyRequestC {
                    connect_key: c"connect-key".as_ptr(),
                    expiration_unix_us,
                    total_uses: u32::MAX,
                    allowed_app_id,
                };
                assert_eq!(
                    sia_pre_authorized_key_sign_request_json(
                        key,
                        &raw const request,
                        &raw mut out,
                        &raw mut err
                    ),
                    SIA_OK
                );
                assert!(err.is_null());
                let actual: serde_json::Value =
                    serde_json::from_str(CStr::from_ptr(out).to_str().unwrap()).unwrap();
                sia_string_free(out);
                let expected = core_key.sign_request(PreAuthorizedKeyRequest {
                    connect_key: "connect-key".to_string(),
                    expiration: sia_storage::DateTime::from_timestamp(seconds, nanos).unwrap(),
                    total_uses: u32::MAX,
                    allowed_app_id: expected_app_id,
                });
                assert_eq!(actual, serde_json::to_value(expected).unwrap());
            }
            sia_pre_authorized_key_free(key);
        }
    }

    #[test]
    fn pre_authorized_key_sign_request_invalid_inputs() {
        unsafe {
            let key = sia_pre_authorized_key_import([2u8; 32].as_ptr());
            let request = PreAuthorizedKeyRequestC {
                connect_key: c"connect-key".as_ptr(),
                expiration_unix_us: 183_000_000,
                total_uses: 1,
                allowed_app_id: std::ptr::null(),
            };
            let null_connect_key = PreAuthorizedKeyRequestC {
                connect_key: std::ptr::null(),
                ..request
            };
            let invalid_expiration = PreAuthorizedKeyRequestC {
                expiration_unix_us: i64::MAX,
                ..request
            };
            for (key, request, status, message) in [
                (
                    std::ptr::null(),
                    &raw const request,
                    SIA_ERR_INVALID_HANDLE,
                    None,
                ),
                (
                    key as *const _,
                    std::ptr::null(),
                    SIA_ERR_INVALID_HANDLE,
                    None,
                ),
                (
                    key as *const _,
                    &raw const null_connect_key,
                    SIA_ERR,
                    Some("connect key is null"),
                ),
                (
                    key as *const _,
                    &raw const invalid_expiration,
                    SIA_ERR,
                    Some("invalid expiration timestamp"),
                ),
            ] {
                let mut sentinel: c_char = 0;
                let original_out = &raw mut sentinel;
                let mut out = original_out;
                let mut err = std::ptr::null_mut();
                assert_eq!(
                    sia_pre_authorized_key_sign_request_json(
                        key,
                        request,
                        &raw mut out,
                        &raw mut err
                    ),
                    status
                );
                assert_eq!(out, original_out);
                if let Some(message) = message {
                    assert!(!err.is_null());
                    assert!(CString::from_raw(err).to_str().unwrap().contains(message));
                } else {
                    assert!(err.is_null());
                }
            }
            sia_pre_authorized_key_free(key);
        }
    }
}
