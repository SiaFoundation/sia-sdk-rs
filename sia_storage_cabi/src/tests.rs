use crate::abi::*;
use crate::builder::*;
use crate::download::*;
use crate::hosts::*;
use crate::mock::*;
use crate::object::*;
use crate::sdk::*;
use crate::shared_sdk::*;
use crate::sharing::*;
use crate::upload::*;
use sia_storage::{Object, Sdk};
use std::ffi::{CStr, CString, c_char};

/// Consumes an out-param error message so a failed assertion can report
/// what Rust actually said rather than just the status code.
unsafe fn take_err(err: *mut c_char) -> String {
    if err.is_null() {
        return "no message".to_string();
    }
    unsafe { CString::from_raw(err) }
        .to_string_lossy()
        .into_owned()
}

fn default_upload_options() -> UploadOptionsC {
    UploadOptionsC {
        data_shards: 0,
        parity_shards: 0,
        set_redundancy: false,
        max_buffered_slabs: 0,
        on_shard: None,
        userdata: 0,
        has_start_offset: false,
        start_offset: 0,
    }
}

fn default_download_options() -> DownloadOptionsC {
    DownloadOptionsC {
        offset: 0,
        has_length: false,
        length: 0,
        max_buffered_chunks: 0,
        on_shard: None,
        userdata: 0,
    }
}

/// Streams a payload out through `sia_upload_*` and back in through
/// `sia_download_*`, against in-process hosts. This is the only test that
/// covers the streaming entry points the Go SDK is built on, and it runs
/// the same Sdk code path production runs.
#[test]
fn mock_upload_download_roundtrip() {
    unsafe {
        let mock = sia_mock_new(40);
        assert!(!mock.is_null());

        let seed = [7u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_mock_sdk(
            mock,
            seed.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sdk,
            &raw mut err,
        );
        assert_eq!(code, SIA_OK, "sia_mock_sdk: {}", take_err(err));
        assert!(!sdk.is_null());

        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err);
        assert_eq!(code, SIA_OK, "sia_upload_start: {}", take_err(err));

        // Larger than one 4 MiB sector so the payload spans several shards
        // and the erasure coder actually runs.
        let payload: Vec<u8> = (0..(9 << 20)).map(|i| (i % 251) as u8).collect();
        let mut err = std::ptr::null_mut();
        let mut wrote = 0usize;
        let code = sia_upload_write(
            up,
            payload.as_ptr(),
            payload.len(),
            std::ptr::null_mut(),
            &raw mut wrote,
            &raw mut err,
        );
        assert_eq!(code, SIA_OK, "sia_upload_write: {}", take_err(err));
        assert_eq!(
            wrote,
            payload.len(),
            "a successful write must report it all"
        );

        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err);
        assert_eq!(code, SIA_OK, "sia_upload_finish: {}", take_err(err));
        sia_upload_free(up);
        assert!(!uploaded.is_null());
        assert_eq!(sia_object_size(uploaded), payload.len() as u64);

        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_download_start(sdk, uploaded, &raw const dopts, &raw mut dl, &raw mut err);
        assert_eq!(code, SIA_OK, "sia_download_start: {}", take_err(err));

        let mut got = Vec::with_capacity(payload.len());
        let mut buf = vec![0u8; 256 << 10];
        loop {
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            let code = sia_download_read(
                dl,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::null_mut(),
                &raw mut n,
                &raw mut err,
            );
            assert_eq!(code, SIA_OK, "sia_download_read: {}", take_err(err));
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        sia_download_free(dl);

        assert_eq!(got.len(), payload.len(), "downloaded a different length");
        assert!(got == payload, "downloaded bytes differ from the upload");

        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A download of an object whose sectors the hosts have dropped must fail
/// rather than return short or hang. This is the failure path the Go side
/// maps onto `ErrNotEnoughShards`.
#[test]
fn download_fails_when_sectors_are_gone() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [9u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_mock_sdk(
            mock,
            seed.as_ptr(),
            std::ptr::null_mut(),
            &raw mut sdk,
            &raw mut err,
        );
        assert_eq!(code, SIA_OK, "sia_mock_sdk: {}", take_err(err));

        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        let payload = vec![3u8; 5 << 20];
        let mut err = std::ptr::null_mut();
        let mut wrote = 0usize;
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        assert_eq!(
            wrote,
            payload.len(),
            "a successful write must report it all"
        );

        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        sia_mock_clear_sectors(mock);

        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_start(sdk, uploaded, &raw const dopts, &raw mut dl, &raw mut err),
            SIA_OK,
            "sia_download_start: {}",
            take_err(err)
        );

        let mut buf = vec![0u8; 256 << 10];
        let read_err = loop {
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            let code = sia_download_read(
                dl,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::null_mut(),
                &raw mut n,
                &raw mut err,
            );
            if code != SIA_OK {
                break (code, take_err(err));
            }
            assert_ne!(n, 0, "download reported a clean EOF after sector loss");
        };
        sia_download_free(dl);

        let (read_code, read_err) = read_err;
        assert_eq!(
            read_code, SIA_ERR_NOT_ENOUGH_SHARDS,
            "the Go side maps the code, not the message: {read_err}"
        );
        assert!(
            read_err.contains("not enough shards"),
            "expected a shard recovery failure, got {read_err}"
        );

        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// The sharing key handle is pure key derivation with no indexer involved,
/// so the whole import, export and free lifecycle is testable here. Export
/// hands back the credential, so a mismatch would leak the wrong key.
#[test]
fn sharing_key_import_export_roundtrip() {
    unsafe {
        let seed = [0x5au8; 32];
        let key = sia_sharing_key_import(seed.as_ptr());
        assert!(!key.is_null());

        let mut exported = [0u8; 32];
        sia_sharing_key_export(key, exported.as_mut_ptr());
        assert_eq!(exported, seed, "export must return the imported seed");

        let mut pk = [0u8; 32];
        sia_sharing_key_public_key(key, pk.as_mut_ptr());
        assert_ne!(pk, [0u8; 32], "public half must be derived, not zero");
        assert_ne!(pk, seed, "public half must not be the seed itself");

        // The same seed must derive the same key, or a recipient handed an
        // exported seed would not reach the same objects.
        let key2 = sia_sharing_key_import(seed.as_ptr());
        let mut pk2 = [0u8; 32];
        sia_sharing_key_public_key(key2, pk2.as_mut_ptr());
        assert_eq!(pk, pk2, "the same seed must derive the same key");

        sia_sharing_key_free(key);
        sia_sharing_key_free(key2);
        sia_sharing_key_free(std::ptr::null_mut());
    }
}

/// Drives the sharing key lifecycle against the mock, which now implements
/// the indexer side of it. Every call here reaches real code rather than an
/// error path, so this covers the entry points a binding needs in order and
/// checks the ownership rules on the ones that hand back allocations.
#[test]
fn sharing_key_lifecycle_against_the_mock() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [13u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let desc = CString::new("test key").unwrap();
        let mut key = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_create_sharing_key(
                sdk,
                desc.as_ptr(),
                false,
                0,
                std::ptr::null_mut(),
                &raw mut key,
                &raw mut err,
            ),
            SIA_OK,
            "sia_sdk_create_sharing_key: {}",
            take_err(err)
        );
        assert!(!key.is_null(), "a created key must come back as a handle");

        // The seed is the whole credential, so exporting one and importing
        // it again has to yield the same public key.
        let mut exported = [0u8; 32];
        sia_sharing_key_export(key, exported.as_mut_ptr());
        let reimported = sia_sharing_key_import(exported.as_ptr());
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        sia_sharing_key_public_key(key, a.as_mut_ptr());
        sia_sharing_key_public_key(reimported, b.as_mut_ptr());
        assert_eq!(a, b, "an exported seed must reimport to the same key");
        sia_sharing_key_free(reimported);

        let mut out_desc = std::ptr::null_mut();
        let mut stats = std::mem::zeroed::<KeyStatsC>();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_sharing_key(
                sdk,
                key,
                std::ptr::null_mut(),
                &raw mut out_desc,
                &raw mut stats,
                &raw mut err
            ),
            SIA_OK,
            "sia_sdk_sharing_key: {}",
            take_err(err)
        );
        assert_eq!(
            CStr::from_ptr(out_desc).to_str().unwrap(),
            "test key",
            "the description must survive the round trip"
        );
        sia_string_free(out_desc);

        let mut recs = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_sharing_keys(
                sdk,
                0,
                10,
                std::ptr::null_mut(),
                &raw mut recs,
                &raw mut err
            ),
            SIA_OK,
            "sia_sdk_sharing_keys: {}",
            take_err(err)
        );
        assert_eq!(sia_key_records_len(recs), 1, "the account has one key");

        let mut listed_key = std::ptr::null_mut();
        let mut listed_desc = std::ptr::null_mut();
        let mut listed_stats = std::mem::zeroed::<KeyStatsC>();
        assert!(
            sia_key_records_at(
                recs,
                0,
                &raw mut listed_key,
                &raw mut listed_desc,
                &raw mut listed_stats
            ),
            "index 0 is in range"
        );
        assert!(
            !sia_key_records_at(
                recs,
                1,
                &raw mut listed_key,
                &raw mut listed_desc,
                &raw mut listed_stats
            ),
            "an out of range index must report false rather than panic"
        );
        sia_sharing_key_free(listed_key);
        sia_string_free(listed_desc);
        sia_key_records_free(recs);

        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_revoke_sharing_key(sdk, key, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_revoke_sharing_key: {}",
            take_err(err)
        );

        sia_sharing_key_free(key);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// The sealed object crossing has to survive a full round trip, because the
/// JSON is what a caller persists. Sealing, encoding, decoding and opening
/// must return an object that still downloads, or a stored object becomes
/// unreadable after a restart.
#[test]
fn sealed_object_json_round_trips() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [31u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        // An uploaded object, so the sealed form carries real slabs and
        // sectors rather than an empty slab list.
        let obj = sia_object_new();
        let meta = b"round trip metadata".to_vec();
        sia_object_set_metadata(obj, meta.as_ptr(), meta.len());
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );
        let payload = vec![17u8; 5 << 20];
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        let mut json = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_object_seal_json(sdk, uploaded, &raw mut json, &raw mut err),
            SIA_OK,
            "sia_object_seal_json: {}",
            take_err(err)
        );
        let encoded = CString::from_raw(json).to_string_lossy().into_owned();

        // The field names are the wire contract a consumer decodes by name.
        for field in [
            "encryptedDataKey",
            "slabs",
            "dataSignature",
            "metadataSignature",
            "createdAt",
            "updatedAt",
        ] {
            assert!(
                encoded.contains(&format!("\"{field}\"")),
                "sealed json is missing {field}, which consumers decode by name"
            );
        }

        let cjson = CString::new(encoded).unwrap();
        let mut reopened = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_object_from_sealed_json(sdk, cjson.as_ptr(), &raw mut reopened, &raw mut err),
            SIA_OK,
            "sia_object_from_sealed_json: {}",
            take_err(err)
        );

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        sia_object_id(uploaded, a.as_mut_ptr());
        sia_object_id(reopened, b.as_mut_ptr());
        assert_eq!(a, b, "the round tripped object has a different id");
        assert_eq!(
            sia_object_size(uploaded),
            sia_object_size(reopened),
            "size changed across the round trip"
        );

        let n = sia_object_metadata(reopened, std::ptr::null_mut(), 0);
        let mut got = vec![0u8; n];
        sia_object_metadata(reopened, got.as_mut_ptr(), n);
        assert_eq!(got, meta, "metadata did not survive the round trip");

        // The reopened object must still be usable, not merely equal.
        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_start(sdk, reopened, &raw const dopts, &raw mut dl, &raw mut err),
            SIA_OK,
            "a round tripped object could not be downloaded: {}",
            take_err(err)
        );
        let mut got = Vec::with_capacity(payload.len());
        let mut buf = vec![0u8; 256 << 10];
        loop {
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_read(
                    dl,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::null_mut(),
                    &raw mut n,
                    &raw mut err
                ),
                SIA_OK,
                "sia_download_read: {}",
                take_err(err)
            );
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        sia_download_free(dl);
        assert!(got == payload, "downloaded bytes differ after a round trip");

        sia_object_free(reopened);
        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A cancelled write must report how many bytes reached the pipe and must
/// leave the handle usable, or a caller cannot tell a resumable partial
/// write from a torn one and will silently corrupt the object by resending
/// bytes that already landed.
#[test]
fn cancelled_write_reports_progress_and_leaves_the_upload_resumable() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [21u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        let payload = vec![4u8; 5 << 20];

        // An already cancelled token makes the outcome deterministic: the
        // biased select takes the cancel branch before any byte moves.
        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut wrote = usize::MAX;
        let mut err = std::ptr::null_mut();
        let code = sia_upload_write(
            up,
            payload.as_ptr(),
            payload.len(),
            cancel,
            &raw mut wrote,
            &raw mut err,
        );
        let msg = take_err(err);
        assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");
        assert_eq!(wrote, 0, "a write cancelled before starting moved no bytes");
        sia_cancel_free(cancel);

        // The handle survived, so the caller can resume from `wrote`.
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "the upload was not resumable after a cancelled write: {}",
            take_err(err)
        );
        assert_eq!(wrote, payload.len());

        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        assert_eq!(sia_object_size(uploaded), payload.len() as u64);

        sia_upload_free(up);
        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Cancelling finish must consume the task rather than detach it. A
/// detached upload runs to completion with nobody observing it, stranding
/// sectors on hosts under an object the caller never receives.
#[test]
fn cancelled_finish_consumes_the_upload() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [23u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_upload_finish(up, cancel, &raw mut uploaded, &raw mut err);
        let msg = take_err(err);
        assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");
        assert!(
            uploaded.is_null(),
            "the out param must be untouched on cancellation"
        );
        sia_cancel_free(cancel);

        // The task was taken and aborted, so the handle is spent rather
        // than left holding a live upload nobody is watching.
        let mut err = std::ptr::null_mut();
        let code = sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err);
        let msg = take_err(err);
        assert_eq!(
            code, SIA_ERR_INVALID_STATE,
            "a cancelled upload must not be finishable again, got {msg}"
        );

        sia_upload_free(up);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// An out of range index must be reported rather than panicking, since a
/// panic unwinding into C is undefined behaviour and aborts the process.
#[test]
fn events_at_rejects_out_of_range() {
    unsafe {
        let evs = Box::into_raw(Box::new(FfiEvents(Vec::new())));
        assert_eq!(sia_events_len(evs), 0);

        let mut id = [0u8; 32];
        let mut deleted = false;
        let mut updated_at = 0i64;
        let mut obj = std::ptr::null_mut();
        assert!(
            !sia_events_at(
                evs,
                0,
                id.as_mut_ptr(),
                &raw mut deleted,
                &raw mut updated_at,
                &raw mut obj
            ),
            "index 0 of an empty list must be rejected"
        );
        assert!(obj.is_null(), "out params must be untouched when rejected");

        sia_events_free(evs);
        sia_events_free(std::ptr::null_mut());
    }
}

/// Same contract as `sia_events_at`, reported in the return value because
/// there is no error out-param on this call either.
#[test]
fn key_records_at_rejects_out_of_range() {
    unsafe {
        let recs = Box::into_raw(Box::new(FfiKeyRecords(Vec::new())));
        assert_eq!(sia_key_records_len(recs), 0);

        let mut key = std::ptr::null_mut();
        let mut desc = std::ptr::null_mut();
        let mut stats = std::mem::zeroed::<KeyStatsC>();
        assert!(
            !sia_key_records_at(recs, 0, &raw mut key, &raw mut desc, &raw mut stats),
            "index 0 of an empty list must be rejected"
        );
        assert!(key.is_null(), "out params must be untouched when rejected");
        assert!(desc.is_null());

        sia_key_records_free(recs);
        sia_key_records_free(std::ptr::null_mut());
    }
}

/// Cancelling the token a blocking read is parked on must unblock it with
/// `SIA_ERR_CANCELLED`, which is what makes Go context cancellation work.
#[test]
fn cancelled_read_returns_cancelled() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [11u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );
        let payload = vec![5u8; 5 << 20];
        let mut err = std::ptr::null_mut();
        let mut wrote = 0usize;
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        assert_eq!(
            wrote,
            payload.len(),
            "a successful write must report it all"
        );
        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_start(sdk, uploaded, &raw const dopts, &raw mut dl, &raw mut err),
            SIA_OK,
            "sia_download_start: {}",
            take_err(err)
        );

        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);

        let mut buf = vec![0u8; 256 << 10];
        let mut n = 0usize;
        let mut err = std::ptr::null_mut();
        let code = sia_download_read(
            dl,
            buf.as_mut_ptr(),
            buf.len(),
            cancel,
            &raw mut n,
            &raw mut err,
        );
        let msg = take_err(err);
        assert_eq!(code, SIA_ERR_CANCELLED, "expected cancellation, got {msg}");

        sia_cancel_free(cancel);
        sia_download_free(dl);
        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// An abandoned add must cost only its own object. Dropping the write half
/// looks like a clean end of input, so the add task commits a short but valid
/// object; without `sia_packed_upload_add_abort` removing it afterwards, a
/// caller whose source failed part way could not tell that object apart from
/// a complete one.
#[test]
fn aborted_add_leaves_no_object() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [31u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        // Three adds, of which the middle one is abandoned part way.
        let sizes = [4096usize, 2048, 8192];
        for (i, len) in sizes.iter().enumerate() {
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_packed_upload_add_begin(packed, &raw mut err),
                SIA_OK,
                "add_begin {i}: {}",
                take_err(err)
            );

            let data = vec![b'a' + i as u8; *len];
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_packed_upload_add_write(
                    packed,
                    data.as_ptr(),
                    data.len(),
                    std::ptr::null_mut(),
                    &raw mut err
                ),
                SIA_OK,
                "add_write {i}: {}",
                take_err(err)
            );

            let mut err = std::ptr::null_mut();
            if i == 1 {
                assert_eq!(
                    sia_packed_upload_add_abort(packed, std::ptr::null_mut(), &raw mut err),
                    SIA_OK,
                    "add_abort: {}",
                    take_err(err)
                );
            } else {
                let mut written = 0u64;
                assert_eq!(
                    sia_packed_upload_add_finish(
                        packed,
                        std::ptr::null_mut(),
                        &raw mut written,
                        &raw mut err
                    ),
                    SIA_OK,
                    "add_finish {i}: {}",
                    take_err(err)
                );
                assert_eq!(written, *len as u64, "add {i} packed the wrong length");
            }
        }

        // Aborting with nothing in progress is a state error, not a silent
        // pop of the object the previous add committed.
        let mut err = std::ptr::null_mut();
        let code = sia_packed_upload_add_abort(packed, std::ptr::null_mut(), &raw mut err);
        let msg = take_err(err);
        assert_eq!(
            code, SIA_ERR_INVALID_STATE,
            "abort with no add in progress must report it, got {msg}"
        );

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(
                packed,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "sia_packed_upload_finalize: {}",
            take_err(err)
        );
        assert_eq!(len, 2, "the abandoned add must contribute no object");

        let slice = std::slice::from_raw_parts(objs, len);
        assert_eq!(sia_object_size(slice[0]), 4096, "first object");
        assert_eq!(sia_object_size(slice[1]), 8192, "third object");
        for o in slice {
            sia_object_free(*o);
        }
        sia_object_array_free(objs, len);

        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// The two failure modes callers most need to branch on get status codes of
/// their own, so the bindings do not have to recover them by matching on the
/// message text. This pins the classification, including the nested case:
/// QueueError::NoMoreHosts reaches the boundary wrapped inside an upload or
/// download failure rather than on its own.
#[test]
fn error_status_classification() {
    use sia_storage::{DownloadError, QueueError, UploadError};

    assert_eq!(
        status_for(&UploadError::NotEnoughShards(2, 3)),
        SIA_ERR_NOT_ENOUGH_SHARDS,
        "an upload short of shards"
    );
    assert_eq!(
        status_for(&DownloadError::NotEnoughShards(1, 10)),
        SIA_ERR_NOT_ENOUGH_SHARDS,
        "a download short of shards"
    );
    assert_eq!(
        status_for(&QueueError::NoMoreHosts),
        SIA_ERR_NO_MORE_HOSTS,
        "host selection out of candidates"
    );

    // Wrapped rather than outermost, which is how it actually arrives.
    let wrapped = UploadError::from(QueueError::NoMoreHosts);
    assert_eq!(
        status_for(&wrapped),
        SIA_ERR_NO_MORE_HOSTS,
        "a queue failure inside an upload failure must still be recognised"
    );

    // The shape the download path actually produces: the AsyncRead impl boxes
    // the error with io::Error::other, and io::Error::source skips the value
    // it wraps, so walking source alone misses this.
    let boxed = std::io::Error::other(DownloadError::NotEnoughShards(0, 10));
    assert_eq!(
        status_for(&boxed),
        SIA_ERR_NOT_ENOUGH_SHARDS,
        "a download error boxed in an io::Error must still be recognised"
    );

    // Anything else stays generic rather than being forced into a sentinel.
    assert_eq!(
        status_for(&QueueError::InsufficientHosts),
        SIA_ERR,
        "an unrelated queue error must not borrow another code"
    );
}

/// A recipient holding only a seed can reach the indexer with no account of
/// its own, and freeing the handle is clean.
#[test]
fn shared_sdk_connects_with_only_a_seed() {
    unsafe {
        let mock = sia_mock_new(40);
        let owner_seed = [21u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                owner_seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let desc = CString::new("recipient key").unwrap();
        let mut key = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_create_sharing_key(
                sdk,
                desc.as_ptr(),
                false,
                0,
                std::ptr::null_mut(),
                &raw mut key,
                &raw mut err,
            ),
            SIA_OK,
            "sia_sdk_create_sharing_key: {}",
            take_err(err)
        );

        // The seed travels to the recipient out of band; it is all they get.
        let mut shared_seed = [0u8; 32];
        sia_sharing_key_export(key, shared_seed.as_mut_ptr());

        let mut shared = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_shared_sdk(
                mock,
                shared_seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut shared,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_shared_sdk: {}",
            take_err(err)
        );
        assert!(!shared.is_null(), "connecting must yield a handle");

        sia_shared_sdk_free(shared);
        sia_sharing_key_free(key);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Every fallible entry point reports a missing handle rather than
/// dereferencing it, and free accepts null the way free(3) does.
#[test]
fn shared_sdk_rejects_null_handles() {
    unsafe {
        let seed = [7u8; 32];
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_shared_sdk(
                std::ptr::null(),
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_ERR_INVALID_HANDLE,
        );
        assert!(err.is_null(), "an absent handle sets no message");

        sia_shared_sdk_free(std::ptr::null_mut());
    }
}

/// The whole recipient path: the owner uploads and attaches an object, then a
/// recipient holding only the seed lists it, fetches it by id, and sees the
/// key's stats. Nothing here touches the owner's SDK.
#[test]
fn shared_sdk_reads_what_the_owner_shared() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [31u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        // Spans more than one sector so the object has several shards.
        let payload: Vec<u8> = (0..(5 << 20)).map(|i| (i % 251) as u8).collect();
        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        // Attaching goes through the indexer, which only knows objects that
        // have been pinned.
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_pin_object(sdk, uploaded, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_pin_object: {}",
            take_err(err)
        );

        let desc = CString::new("shared with a recipient").unwrap();
        let mut key = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_create_sharing_key(
                sdk,
                desc.as_ptr(),
                false,
                0,
                std::ptr::null_mut(),
                &raw mut key,
                &raw mut err,
            ),
            SIA_OK,
            "sia_sdk_create_sharing_key: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_share_object(sdk, key, uploaded, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_share_object: {}",
            take_err(err)
        );

        let mut seed = [0u8; 32];
        sia_sharing_key_export(key, seed.as_mut_ptr());
        let mut shared = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_shared_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut shared,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_shared_sdk: {}",
            take_err(err)
        );

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_objects(
                shared,
                0,
                0,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "sia_shared_sdk_objects: {}",
            take_err(err)
        );
        assert_eq!(len, 1, "the key has exactly one object attached");

        let listed = std::slice::from_raw_parts(objs, len)[0];
        assert_eq!(
            sia_object_size(listed),
            payload.len() as u64,
            "the recipient must decrypt the object's real size"
        );
        let mut id = [0u8; 32];
        sia_object_id(listed, id.as_mut_ptr());

        // Fetching the same object by id must agree with the listing.
        let mut one = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_object(
                shared,
                id.as_ptr(),
                std::ptr::null_mut(),
                &raw mut one,
                &raw mut err
            ),
            SIA_OK,
            "sia_shared_sdk_object: {}",
            take_err(err)
        );
        let mut id2 = [0u8; 32];
        sia_object_id(one, id2.as_mut_ptr());
        assert_eq!(id, id2, "by id must return the object that was asked for");
        assert_eq!(sia_object_size(one), payload.len() as u64);

        let mut stats = std::mem::zeroed::<KeyStatsC>();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_stats(shared, std::ptr::null_mut(), &raw mut stats, &raw mut err),
            SIA_OK,
            "sia_shared_sdk_stats: {}",
            take_err(err)
        );
        assert_eq!(stats.object_count, 1, "stats must see the attached object");

        sia_object_free(one);
        sia_object_array_free(objs, len);
        sia_shared_sdk_free(shared);
        sia_object_free(uploaded);
        sia_sharing_key_free(key);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A recipient downloads a shared object, and the transfer survives the shared
/// SDK being freed underneath it. That outliving is deliberate: the download
/// clones the token refresh so it stays funded for longer than a token's five
/// minute validity.
///
/// What this pins down is that freeing the handle mid transfer is safe and the
/// download still completes correctly. It does not exercise the refresh
/// itself, since a transfer this short never outlives the tokens it started
/// with.
#[test]
fn shared_sdk_download_outlives_the_handle() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [43u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let payload: Vec<u8> = (0..(5 << 20)).map(|i| (i % 241) as u8).collect();
        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_pin_object(sdk, uploaded, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_pin_object: {}",
            take_err(err)
        );

        let desc = CString::new("download key").unwrap();
        let mut key = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_create_sharing_key(
                sdk,
                desc.as_ptr(),
                false,
                0,
                std::ptr::null_mut(),
                &raw mut key,
                &raw mut err,
            ),
            SIA_OK,
            "sia_sdk_create_sharing_key: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_share_object(sdk, key, uploaded, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_share_object: {}",
            take_err(err)
        );

        let mut seed = [0u8; 32];
        sia_sharing_key_export(key, seed.as_mut_ptr());
        let mut shared = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_shared_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut shared,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_shared_sdk: {}",
            take_err(err)
        );

        // The recipient works from the object the key handed it, not the
        // owner's handle.
        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_objects(
                shared,
                0,
                0,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "sia_shared_sdk_objects: {}",
            take_err(err)
        );
        assert_eq!(len, 1);
        let listed = std::slice::from_raw_parts(objs, len)[0];

        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_download_start(
                shared,
                listed,
                &raw const dopts,
                &raw mut dl,
                &raw mut err
            ),
            SIA_OK,
            "sia_shared_sdk_download_start: {}",
            take_err(err)
        );

        // Everything the recipient held is released before a single byte is
        // read. Only the download keeps the transfer alive from here.
        sia_object_array_free(objs, len);
        sia_shared_sdk_free(shared);

        let mut got = Vec::with_capacity(payload.len());
        let mut buf = vec![0u8; 256 << 10];
        loop {
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_read(
                    dl,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::null_mut(),
                    &raw mut n,
                    &raw mut err,
                ),
                SIA_OK,
                "sia_download_read after the shared sdk was freed: {}",
                take_err(err)
            );
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        sia_download_free(dl);

        assert_eq!(got.len(), payload.len(), "downloaded a different length");
        assert!(got == payload, "downloaded bytes differ from the upload");

        sia_object_free(uploaded);
        sia_object_free(obj);
        sia_sharing_key_free(key);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

fn no_host_filters() -> HostQueryC {
    HostQueryC {
        has_location: false,
        latitude: 0.0,
        longitude: 0.0,
        offset: 0,
        limit: 0,
        country: std::ptr::null(),
    }
}

/// Every HostQuery field survives the crossing. This tests the conversion
/// directly rather than through the mock, because the mock's indexer honours
/// only offset and limit and ignores location, protocol and country, so a
/// round trip through it would prove nothing about those three.
#[test]
fn host_query_marshals_every_field() {
    unsafe {
        let q = no_host_filters();
        let out = make_host_query(&q).expect("an empty query is valid");
        assert!(
            out.location.is_none(),
            "no location means no proximity sort"
        );
        assert_eq!(
            out.protocol,
            Some(sia_storage::Protocol::SiaMux),
            "listings are always scoped to the only protocol we can dial"
        );
        assert!(out.country.is_none());
        assert!(out.offset.is_none(), "0 means the indexer's default");
        assert!(out.limit.is_none());

        let mut q = no_host_filters();
        q.has_location = true;
        q.latitude = 52.37;
        q.longitude = 4.90;
        q.offset = 20;
        q.limit = 5;
        let country = CString::new("NL").unwrap();
        q.country = country.as_ptr();
        let out = make_host_query(&q).expect("a full query is valid");
        let loc = out.location.expect("location must cross");
        assert_eq!(loc.latitude, 52.37);
        assert_eq!(loc.longitude, 4.90);
        assert_eq!(out.offset, Some(20));
        assert_eq!(out.limit, Some(5));
        assert_eq!(out.country.as_deref(), Some("NL"));
        assert_eq!(out.protocol, Some(sia_storage::Protocol::SiaMux));

        // has_location false must win over whatever the coords hold.
        let mut q = no_host_filters();
        q.latitude = 1.0;
        q.longitude = 2.0;
        let out = make_host_query(&q).unwrap();
        assert!(
            out.location.is_none(),
            "has_location false must ignore the coords"
        );
    }
}

/// The listing crosses as JSON in the shape a consumer decodes, and the paging
/// the mock does honour reaches it.
#[test]
fn sdk_hosts_lists_as_json() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [61u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let fetch = |q: &HostQueryC| -> serde_json::Value {
            let mut out = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_sdk_hosts(
                    sdk,
                    &raw const *q,
                    std::ptr::null_mut(),
                    &raw mut out,
                    &raw mut err
                ),
                SIA_OK,
                "sia_sdk_hosts: {}",
                take_err(err)
            );
            let json = CStr::from_ptr(out).to_str().unwrap().to_string();
            sia_string_free(out);
            serde_json::from_str(&json).expect("hosts must be valid JSON")
        };

        let all = fetch(&no_host_filters());
        let hosts = all.as_array().expect("a JSON array");
        assert_eq!(hosts.len(), 40, "every mock host should be listed");

        // The field names a consumer decodes into, not just "it parsed".
        let first = &hosts[0];
        assert!(first["publicKey"].is_string(), "publicKey: {first}");
        assert!(
            first["goodForUpload"].is_boolean(),
            "goodForUpload: {first}"
        );
        assert!(first["countryCode"].is_string(), "countryCode: {first}");
        let addrs = first["addresses"].as_array().expect("addresses array");
        assert!(!addrs.is_empty(), "a host must carry an address");
        assert!(addrs[0]["protocol"].is_string(), "protocol: {first}");
        assert!(addrs[0]["address"].is_string(), "address: {first}");

        let mut q = no_host_filters();
        q.limit = 5;
        assert_eq!(fetch(&q).as_array().unwrap().len(), 5, "limit must apply");
        q.offset = 38;
        q.limit = 10;
        assert_eq!(
            fetch(&q).as_array().unwrap().len(),
            2,
            "offset must skip, and a limit past the end must not wrap"
        );

        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// The recipient sees the hosts serving the key's objects, scoped to the key.
#[test]
fn shared_sdk_hosts_are_scoped_to_the_key() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [67u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let desc = CString::new("host listing key").unwrap();
        let mut key = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_create_sharing_key(
                sdk,
                desc.as_ptr(),
                false,
                0,
                std::ptr::null_mut(),
                &raw mut key,
                &raw mut err,
            ),
            SIA_OK,
            "sia_sdk_create_sharing_key: {}",
            take_err(err)
        );
        let mut seed = [0u8; 32];
        sia_sharing_key_export(key, seed.as_mut_ptr());

        let mut shared = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_shared_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut shared,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_shared_sdk: {}",
            take_err(err)
        );

        let q = no_host_filters();
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_shared_sdk_hosts(
                shared,
                &raw const q,
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_OK,
            "sia_shared_sdk_hosts: {}",
            take_err(err)
        );
        let json = CStr::from_ptr(out).to_str().unwrap().to_string();
        sia_string_free(out);
        let hosts: serde_json::Value =
            serde_json::from_str(&json).expect("hosts must be valid JSON");
        let hosts = hosts.as_array().expect("a JSON array");
        assert!(
            !hosts.is_empty(),
            "a key with tokens must see the hosts serving it"
        );
        assert!(hosts[0]["publicKey"].is_string());

        sia_shared_sdk_free(shared);
        sia_sharing_key_free(key);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Both listings report a missing handle rather than dereferencing it.
#[test]
fn hosts_reject_null_handles() {
    unsafe {
        let q = no_host_filters();
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_hosts(
                std::ptr::null(),
                &raw const q,
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_ERR_INVALID_HANDLE,
        );
        assert_eq!(
            sia_shared_sdk_hosts(
                std::ptr::null(),
                &raw const q,
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_ERR_INVALID_HANDLE,
        );
        assert!(err.is_null(), "an absent handle sets no message");
    }
}

/// Uploads `data` to a fresh object and returns the pinned result.
unsafe fn upload_object_for_test(sdk: *const Sdk, data: &[u8]) -> *mut Object {
    unsafe {
        let obj = sia_object_new();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, obj, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                data.as_ptr(),
                data.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut out, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);
        sia_object_free(obj);
        out
    }
}

/// Reads an object back in full.
unsafe fn download_all(sdk: *const Sdk, obj: *const Object) -> Vec<u8> {
    unsafe {
        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_start(sdk, obj, &raw const dopts, &raw mut dl, &raw mut err),
            SIA_OK,
            "sia_download_start: {}",
            take_err(err)
        );
        let mut got = Vec::new();
        let mut buf = vec![0u8; 256 << 10];
        loop {
            let mut n = 0usize;
            let mut err = std::ptr::null_mut();
            assert_eq!(
                sia_download_read(
                    dl,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::null_mut(),
                    &raw mut n,
                    &raw mut err
                ),
                SIA_OK,
                "sia_download_read: {}",
                take_err(err)
            );
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        sia_download_free(dl);
        got
    }
}

/// start_offset rewrites a range in place rather than appending, and the
/// bytes outside the range survive untouched.
#[test]
fn upload_start_offset_overwrites_in_place() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [71u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let original: Vec<u8> = (0..(6 << 20)).map(|i| (i % 251) as u8).collect();
        let uploaded = upload_object_for_test(sdk, &original);
        assert_eq!(sia_object_size(uploaded), original.len() as u64);

        // Overwrite a window in the middle.
        let at = 1 << 20;
        let patch = vec![0xAAu8; 4096];
        let mut opts = default_upload_options();
        opts.has_start_offset = true;
        opts.start_offset = at as u64;
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(sdk, uploaded, &raw const opts, &raw mut up, &raw mut err),
            SIA_OK,
            "sia_upload_start with a start offset: {}",
            take_err(err)
        );
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                patch.as_ptr(),
                patch.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut rewritten = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut rewritten, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        assert_eq!(
            sia_object_size(rewritten),
            original.len() as u64,
            "an overwrite inside the object must not change its size"
        );

        // An id is derived from the object's slabs, and an overwrite replaces
        // the ones covering its range, so the result is a different object.
        let mut before = [0u8; 32];
        let mut after = [0u8; 32];
        sia_object_id(uploaded, before.as_mut_ptr());
        sia_object_id(rewritten, after.as_mut_ptr());
        assert_ne!(
            before, after,
            "rewriting slabs must move the id, whatever the docs once said"
        );

        let mut expected = original.clone();
        expected[at..at + patch.len()].copy_from_slice(&patch);
        let got = download_all(sdk, rewritten);
        assert_eq!(got.len(), expected.len(), "length changed");
        assert!(
            got == expected,
            "the rewritten range or its surroundings differ"
        );

        sia_object_free(rewritten);
        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// An offset past the end of the object is the caller's mistake and gets its
/// own status, so Go can branch on it without matching the message.
#[test]
fn upload_start_offset_past_the_end_is_out_of_range() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [73u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let original = vec![1u8; 4096];
        let uploaded = upload_object_for_test(sdk, &original);

        let mut opts = default_upload_options();
        opts.has_start_offset = true;
        opts.start_offset = original.len() as u64 + 1;
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let code = sia_upload_start(sdk, uploaded, &raw const opts, &raw mut up, &raw mut err);
        // The range is only checked once the upload runs, so a failure may
        // surface from either call.
        let code = if code == SIA_OK {
            let mut out = std::ptr::null_mut();
            let mut err2 = std::ptr::null_mut();
            let c = sia_upload_finish(up, std::ptr::null_mut(), &raw mut out, &raw mut err2);
            sia_upload_free(up);
            err = err2;
            c
        } else {
            code
        };
        assert_eq!(
            code,
            SIA_ERR_OUT_OF_RANGE,
            "an offset past the end must classify: {}",
            take_err(err)
        );

        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A packed add always appends, so a start offset there is refused rather
/// than quietly dropped.
#[test]
fn packed_upload_refuses_a_start_offset() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [79u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let mut opts = default_upload_options();
        opts.has_start_offset = true;
        opts.start_offset = 64;
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_ERR_INVALID_STATE,
        );
        assert!(
            take_err(err).contains("start offset"),
            "the refusal must say why"
        );

        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Truncation shortens the object, leaves the original alone, and the result
/// downloads as the leading prefix of what was uploaded.
#[test]
fn object_truncate_shortens_and_copies() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [83u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let original: Vec<u8> = (0..(6 << 20)).map(|i| (i % 251) as u8).collect();
        let uploaded = upload_object_for_test(sdk, &original);

        let cut = 1_000_000u64;
        let short = sia_object_truncate(uploaded, cut);
        assert!(!short.is_null());
        assert_eq!(sia_object_size(short), cut, "truncate must resize");
        assert_eq!(
            sia_object_size(uploaded),
            original.len() as u64,
            "the original must be untouched"
        );

        // The bytes have to be the real prefix, not just the right length.
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_pin_object(sdk, short, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_pin_object: {}",
            take_err(err)
        );
        let got = download_all(sdk, short);
        assert_eq!(got.len(), cut as usize, "downloaded a different length");
        assert!(
            got == original[..cut as usize],
            "the truncated object must download as the original's prefix"
        );

        // At or past the current size it is a plain copy.
        let same = sia_object_truncate(uploaded, original.len() as u64);
        assert_eq!(sia_object_size(same), original.len() as u64);
        let longer = sia_object_truncate(uploaded, original.len() as u64 * 2);
        assert_eq!(
            sia_object_size(longer),
            original.len() as u64,
            "a length past the end must not grow the object"
        );

        // Truncating to nothing is legal and yields an empty object.
        let empty = sia_object_truncate(uploaded, 0);
        assert_eq!(sia_object_size(empty), 0);

        assert!(
            sia_object_truncate(std::ptr::null(), 0).is_null(),
            "a null object must return null rather than be dereferenced"
        );

        sia_object_free(empty);
        sia_object_free(longer);
        sia_object_free(same);
        sia_object_free(short);
        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A slab id taken from an object fetches that slab back from the indexer,
/// and the sectors it reports are the ones the object references.
#[test]
fn sdk_slab_fetches_by_id_from_an_object() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [89u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        // Two sectors' worth so the object has more than one slab to index.
        let payload: Vec<u8> = (0..(9 << 20)).map(|i| (i % 251) as u8).collect();
        let uploaded = upload_object_for_test(sdk, &payload);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_pin_object(sdk, uploaded, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_pin_object: {}",
            take_err(err)
        );

        let count = sia_object_slab_count(uploaded);
        assert!(count > 0, "an uploaded object must reference slabs");

        let mut id = [0u8; 32];
        assert!(
            sia_object_slab_id_at(uploaded, 0, id.as_mut_ptr()),
            "the first slab id must be readable"
        );
        assert_ne!(id, [0u8; 32], "a slab id must not be all zeroes");

        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_slab(
                sdk,
                id.as_ptr(),
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_OK,
            "sia_sdk_slab: {}",
            take_err(err)
        );
        let json = CStr::from_ptr(out).to_str().unwrap().to_string();
        sia_string_free(out);
        let slab: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        // The fields a consumer decodes, and the identity that was asked for.
        assert!(slab["encryptionKey"].is_string(), "encryptionKey: {slab}");
        assert!(slab["minShards"].is_number(), "minShards: {slab}");
        let sectors = slab["sectors"].as_array().expect("sectors array");
        assert!(!sectors.is_empty(), "a pinned slab must have sectors");
        assert!(sectors[0]["root"].is_string(), "root: {slab}");
        assert!(sectors[0]["hostKey"].is_string(), "hostKey: {slab}");

        // Out of range must report rather than write.
        let mut untouched = [7u8; 32];
        assert!(
            !sia_object_slab_id_at(uploaded, count, untouched.as_mut_ptr()),
            "an index past the end must return false"
        );
        assert_eq!(untouched, [7u8; 32], "a refused read must not write");
        assert_eq!(sia_object_slab_count(std::ptr::null()), 0);
        assert!(!sia_object_slab_id_at(
            std::ptr::null(),
            0,
            untouched.as_mut_ptr()
        ));

        // An id nothing was pinned under is an error, not an empty result.
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_ne!(
            sia_sdk_slab(
                sdk,
                [0u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut out,
                &raw mut err
            ),
            SIA_OK,
            "an unknown slab id must fail"
        );
        let _ = take_err(err);

        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Scans `text` for every `sia_*` name immediately followed by `(`, which is
/// what a declaration or a definition looks like and what a prose mention of
/// one does not.
fn sia_symbols_called_in(text: &str) -> std::collections::BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut found = std::collections::BTreeSet::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find("sia_") {
        let start = i + rel;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_lowercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'_')
        {
            end += 1;
        }
        if bytes.get(end) == Some(&b'(') {
            found.insert(text[start..end].to_string());
        }
        i = start + 4;
    }
    found
}

/// The header is hand maintained, so nothing but this keeps it in step with
/// what the crate exports. A declaration with no export fails at link time in
/// a consumer's project; an export with no declaration is invisible to every C
/// caller.
///
/// Must stay under the `mock` feature: this scans the header as text, so the
/// `#ifdef SIA_STORAGE_MOCK` block always counts as declared.
#[test]
fn header_declares_exactly_what_the_crate_exports() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let header = std::fs::read_to_string(root.join("include/sia_storage.h"))
        .expect("the vendored header must be readable");
    let declared = sia_symbols_called_in(&header);

    // Read the directory rather than listing modules, so a new file cannot
    // add an export this test never looks at.
    let mut exported = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(root.join("src")).expect("src must be readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("source must be readable");
        for (i, _) in src.match_indices("extern \"C\" fn ") {
            let rest = &src[i + "extern \"C\" fn ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if name.starts_with("sia_") {
                exported.insert(name);
            }
        }
    }

    assert!(
        !declared.is_empty() && !exported.is_empty(),
        "the scan found nothing, so it is broken rather than passing"
    );

    let missing_decl: Vec<_> = exported.difference(&declared).collect();
    let missing_export: Vec<_> = declared.difference(&exported).collect();
    assert!(
        missing_decl.is_empty() && missing_export.is_empty(),
        "header and exports disagree.\n  exported but not declared (unreachable from C): {missing_decl:?}\n  declared but not exported (links will fail): {missing_export:?}"
    );
}

/// A null object uploads into a fresh one, so the common case owns a single
/// handle rather than an empty object it has to remember to free alongside the
/// different object finish hands back.
#[test]
fn upload_start_accepts_a_null_object() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [97u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let payload: Vec<u8> = (0..(5 << 20)).map(|i| (i % 251) as u8).collect();
        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(
                sdk,
                std::ptr::null(),
                &raw const opts,
                &raw mut up,
                &raw mut err
            ),
            SIA_OK,
            "a null object must start a fresh upload: {}",
            take_err(err)
        );
        let mut wrote = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        let mut obj = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut obj, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        assert_eq!(sia_object_size(obj), payload.len() as u64);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_sdk_pin_object(sdk, obj, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "sia_sdk_pin_object: {}",
            take_err(err)
        );
        let got = download_all(sdk, obj);
        assert!(got == payload, "the fresh object must round trip");

        sia_object_free(obj);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A cancelled abort says so, and leaves the add observable rather than
/// detaching it: the writer is already gone, so a second abort finishes the
/// job and the object still goes. Reporting SIA_OK here would tell a caller
/// the object was discarded when it was not.
#[test]
fn cancelled_add_abort_reports_cancelled_and_stays_retryable() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [101u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        // One object that stays, then one the caller abandons.
        let keep = vec![b'k'; 4096];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_OK,
            "add_begin: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_write(
                packed,
                keep.as_ptr(),
                keep.len(),
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "add_write: {}",
            take_err(err)
        );
        let mut n = 0u64;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_finish(packed, std::ptr::null_mut(), &raw mut n, &raw mut err),
            SIA_OK,
            "add_finish: {}",
            take_err(err)
        );

        let regret = vec![b'r'; 2048];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_OK,
            "add_begin 2: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_write(
                packed,
                regret.as_ptr(),
                regret.len(),
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "add_write 2: {}",
            take_err(err)
        );

        // Abort with a token that has already fired.
        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_abort(packed, cancel, &raw mut err),
            SIA_ERR_CANCELLED,
            "a cancelled abort must not report success"
        );
        let _ = take_err(err);
        sia_cancel_free(cancel);

        // The add was not detached, so a retry completes it and discards.
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_abort(packed, std::ptr::null_mut(), &raw mut err),
            SIA_OK,
            "retrying the abort: {}",
            take_err(err)
        );

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(
                packed,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "finalize: {}",
            take_err(err)
        );
        assert_eq!(len, 1, "only the kept object survives the abort");
        let listed = std::slice::from_raw_parts(objs, len)[0];
        assert_eq!(sia_object_size(listed), keep.len() as u64);

        sia_object_array_free(objs, len);
        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A cancelled add_finish leaves the add in progress rather than detaching it,
/// so a retry consumes the same task and reports what it wrote. Detaching left
/// the object's fate to whichever of the task and finalize reached the mutex
/// first, which a caller getting SIA_ERR_CANCELLED could not observe.
#[test]
fn cancelled_add_finish_stays_retryable() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [103u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        let payload = vec![b'p'; 4096];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_OK,
            "add_begin: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_write(
                packed,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "add_write: {}",
            take_err(err)
        );

        // Finish with a token that has already fired.
        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut n = 0u64;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_finish(packed, cancel, &raw mut n, &raw mut err),
            SIA_ERR_CANCELLED,
            "a cancelled finish must report cancellation"
        );
        let _ = take_err(err);
        sia_cancel_free(cancel);

        // The task was not detached, so the same add finishes on retry.
        let mut n = 0u64;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_finish(packed, std::ptr::null_mut(), &raw mut n, &raw mut err),
            SIA_OK,
            "retrying the finish: {}",
            take_err(err)
        );
        assert_eq!(
            n,
            payload.len() as u64,
            "the retry reports what the add wrote"
        );

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(
                packed,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "finalize: {}",
            take_err(err)
        );
        assert_eq!(len, 1, "the object landed exactly once");
        let listed = std::slice::from_raw_parts(objs, len)[0];
        assert_eq!(sia_object_size(listed), payload.len() as u64);

        sia_object_array_free(objs, len);
        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// The getters answer during an add. They used to take the same lock the add
/// holds from add_begin until EOF, so a caller asking "does the next object
/// fit?" from the thread driving the add waited for an EOF only it could send.
#[test]
fn packed_getters_do_not_wait_on_an_add() {
    unsafe {
        let mock = sia_mock_new(40);
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                [107u8; 32].as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        let slab = sia_packed_upload_optimal_data_size(packed);
        assert!(slab > 0);
        assert_eq!(sia_packed_upload_remaining(packed), slab);
        assert_eq!(sia_packed_upload_length(packed), 0);

        let payload = vec![b'g'; 8192];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_OK,
            "add_begin: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_write(
                packed,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "add_write: {}",
            take_err(err)
        );

        // Wait for the add task to actually hold the lock, so what follows
        // tests the contended path instead of racing it. The pipe is 16 MiB,
        // so the write above returned without yielding and the task may not
        // have reached its lock yet. Once it has, it keeps it until EOF, which
        // only this thread can send, so there is no race the other way.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while packed
            .as_ref()
            .expect("live handle")
            .inner
            .try_lock()
            .is_ok()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the add task never took the lock"
            );
            std::thread::yield_now();
        }

        assert_eq!(
            sia_packed_upload_remaining(packed),
            slab,
            "during an add the figures are the ones from before it began"
        );
        assert_eq!(sia_packed_upload_length(packed), 0);

        let mut n = 0u64;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_finish(packed, std::ptr::null_mut(), &raw mut n, &raw mut err),
            SIA_OK,
            "add_finish: {}",
            take_err(err)
        );

        // Settled once the add is done.
        assert_eq!(sia_packed_upload_length(packed), payload.len() as u64);
        assert_eq!(
            sia_packed_upload_remaining(packed),
            slab - payload.len() as u64
        );

        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A wait a cancelled call left running stays attached to the handle, so a Go
/// caller polling with a deadline does not throw away a request the user may
/// already have approved.
#[test]
fn cancelled_wait_for_approval_reattaches() {
    let (approve, approved) = tokio::sync::oneshot::channel::<()>();
    let waiting = runtime().spawn(async move {
        let _ = approved.await;
        Err(sia_storage::BuilderError::RequestExpired)
    });
    // Stands in for a builder that has a request out. Nothing outside the
    // crate can reach this state without an indexer to talk to.
    let builder = Box::into_raw(Box::new(FfiBuilder(std::sync::Mutex::new(
        BuilderState::Waiting(waiting),
    ))));

    unsafe {
        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_builder_wait_for_approval(builder, cancel, &raw mut err),
            SIA_ERR_CANCELLED,
            "{}",
            take_err(err)
        );
        sia_cancel_free(cancel);

        // The wait outlived the cancelled call, so the approval it is still
        // watching for lands on the very next one.
        approve.send(()).expect("the wait is still running");
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_builder_wait_for_approval(builder, std::ptr::null_mut(), &raw mut err),
            SIA_ERR_REQUEST_EXPIRED,
            "a cancelled wait must be resumable, not leave the builder consumed: {}",
            take_err(err)
        );
        take_err(err);

        sia_builder_free(builder);
    }
}

/// A C caller with nothing to send passes a null pointer and a zero length.
/// The writes take it as a no-op, and the read refuses rather than answering
/// with the value that means EOF.
#[test]
fn empty_buffers_are_not_read_as_end_of_stream() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [23u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(
                sdk,
                std::ptr::null(),
                &raw const opts,
                &raw mut up,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        let mut wrote = 7usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "an empty write: {}",
            take_err(err)
        );
        assert_eq!(wrote, 0, "nothing was written");

        // The upload still takes real data afterwards.
        let payload = vec![9u8; 4096];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );
        assert_eq!(wrote, payload.len());

        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);

        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_add_begin: {}",
            take_err(err)
        );
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_write(
                packed,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "an empty add write: {}",
            take_err(err)
        );
        sia_packed_upload_free(packed);

        let dopts = default_download_options();
        let mut dl = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_start(sdk, uploaded, &raw const dopts, &raw mut dl, &raw mut err),
            SIA_OK,
            "sia_download_start: {}",
            take_err(err)
        );

        let mut n = 7usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_read(
                dl,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &raw mut n,
                &raw mut err
            ),
            SIA_ERR,
            "a read with no room must not report the value that means EOF"
        );
        take_err(err);
        assert_eq!(n, 7, "a rejected read leaves the out param alone");

        // The download is still good for a real read.
        let mut buf = vec![0u8; 8192];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_download_read(
                dl,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::null_mut(),
                &raw mut n,
                &raw mut err
            ),
            SIA_OK,
            "sia_download_read: {}",
            take_err(err)
        );
        assert_eq!(n, payload.len(), "the object is one short read");

        sia_download_free(dl);
        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A caller that does not want the byte count passes NULL for it. The header
/// allows that, so nothing may write through the pointer.
#[test]
fn upload_write_accepts_a_null_written() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [31u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(
                sdk,
                std::ptr::null(),
                &raw const opts,
                &raw mut up,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        let payload = vec![5u8; 4096];
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_write(
                up,
                payload.as_ptr(),
                payload.len(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_write: {}",
            take_err(err)
        );

        let mut uploaded = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_finish(up, std::ptr::null_mut(), &raw mut uploaded, &raw mut err),
            SIA_OK,
            "sia_upload_finish: {}",
            take_err(err)
        );
        sia_upload_free(up);
        assert_eq!(sia_object_size(uploaded), payload.len() as u64);

        sia_object_free(uploaded);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A caller passing 0 means no logging. It used to be the one value that
/// turned everything on, since the filter fell through to Trace.
#[test]
fn logger_level_zero_is_off() {
    assert_eq!(level_filter(0), log::LevelFilter::Off);
    assert_eq!(level_filter(-1), log::LevelFilter::Off);
    assert_eq!(level_filter(1), log::LevelFilter::Error);
    assert_eq!(level_filter(5), log::LevelFilter::Trace);
    assert_eq!(level_filter(99), log::LevelFilter::Trace, "past the scale");
}

/// Reading an index twice must be reported. The read moves the object out, so
/// a repeat would otherwise answer with a null object and deleted false,
/// which is exactly what a deletion event looks like.
#[test]
fn events_at_rejects_a_second_read() {
    unsafe {
        let evs = Box::into_raw(Box::new(FfiEvents(vec![FfiEvent {
            id: [3u8; 32],
            deleted: false,
            updated_at_us: 1_700_000_000_000_000,
            object: Some(Box::new(Object::default())),
            taken: false,
        }])));

        let mut id = [0u8; 32];
        let mut deleted = true;
        let mut updated_at = 0i64;
        let mut obj = std::ptr::null_mut();
        assert!(
            sia_events_at(
                evs,
                0,
                id.as_mut_ptr(),
                &raw mut deleted,
                &raw mut updated_at,
                &raw mut obj
            ),
            "the first read must succeed"
        );
        assert_eq!(id, [3u8; 32]);
        assert!(!deleted);
        assert_eq!(updated_at, 1_700_000_000_000_000);
        assert!(!obj.is_null(), "the object transfers on the first read");
        sia_object_free(obj);

        // A live address rather than a bare sentinel, so an out param the call
        // wrote would be visible without inventing an invalid pointer.
        let mut untouched = Object::default();
        let mut id2 = [0u8; 32];
        let mut deleted2 = true;
        let mut updated_at2 = 7i64;
        let mut obj2: *mut Object = &raw mut untouched;
        assert!(
            !sia_events_at(
                evs,
                0,
                id2.as_mut_ptr(),
                &raw mut deleted2,
                &raw mut updated_at2,
                &raw mut obj2
            ),
            "the second read must not pass for a deletion"
        );
        assert_eq!(id2, [0u8; 32], "out params must be untouched when rejected");
        assert!(deleted2);
        assert_eq!(updated_at2, 7);
        assert_eq!(obj2, &raw mut untouched);

        sia_events_free(evs);
    }
}

/// The header mirrors these five structs by hand, and the symbol parity test
/// only covers function names. A field added, reordered or resized shifts
/// every offset past it, which C reads as whatever now sits there.
///
/// The offsets are the C layout of the header's declarations on a 64 bit
/// target, which is what the Go bindings ship archives for.
#[test]
#[cfg(target_pointer_width = "64")]
fn header_structs_keep_their_layout() {
    use std::mem::{align_of, offset_of, size_of};

    // sia_shard_progress_t
    assert_eq!(size_of::<ShardProgressC>(), 64, "sia_shard_progress_t");
    assert_eq!(align_of::<ShardProgressC>(), 8, "sia_shard_progress_t");
    assert_eq!(offset_of!(ShardProgressC, host_key), 0);
    assert_eq!(offset_of!(ShardProgressC, shard_size), 32);
    assert_eq!(offset_of!(ShardProgressC, shard_index), 40);
    assert_eq!(offset_of!(ShardProgressC, slab_index), 48);
    assert_eq!(offset_of!(ShardProgressC, elapsed_us), 56);

    // sia_upload_options_t
    assert_eq!(size_of::<UploadOptionsC>(), 48, "sia_upload_options_t");
    assert_eq!(align_of::<UploadOptionsC>(), 8, "sia_upload_options_t");
    assert_eq!(offset_of!(UploadOptionsC, data_shards), 0);
    assert_eq!(offset_of!(UploadOptionsC, parity_shards), 1);
    assert_eq!(offset_of!(UploadOptionsC, set_redundancy), 2);
    assert_eq!(offset_of!(UploadOptionsC, max_buffered_slabs), 8);
    assert_eq!(offset_of!(UploadOptionsC, on_shard), 16);
    assert_eq!(offset_of!(UploadOptionsC, userdata), 24);
    assert_eq!(offset_of!(UploadOptionsC, has_start_offset), 32);
    assert_eq!(offset_of!(UploadOptionsC, start_offset), 40);

    // sia_download_options_t
    assert_eq!(size_of::<DownloadOptionsC>(), 48, "sia_download_options_t");
    assert_eq!(align_of::<DownloadOptionsC>(), 8, "sia_download_options_t");
    assert_eq!(offset_of!(DownloadOptionsC, offset), 0);
    assert_eq!(offset_of!(DownloadOptionsC, has_length), 8);
    assert_eq!(offset_of!(DownloadOptionsC, length), 16);
    assert_eq!(offset_of!(DownloadOptionsC, max_buffered_chunks), 24);
    assert_eq!(offset_of!(DownloadOptionsC, on_shard), 32);
    assert_eq!(offset_of!(DownloadOptionsC, userdata), 40);

    // sia_key_stats_t
    assert_eq!(size_of::<KeyStatsC>(), 56, "sia_key_stats_t");
    assert_eq!(align_of::<KeyStatsC>(), 8, "sia_key_stats_t");
    assert_eq!(offset_of!(KeyStatsC, object_count), 0);
    assert_eq!(offset_of!(KeyStatsC, object_size), 8);
    assert_eq!(offset_of!(KeyStatsC, pinned_data), 16);
    assert_eq!(offset_of!(KeyStatsC, pinned_size), 24);
    assert_eq!(offset_of!(KeyStatsC, created_at_unix_us), 32);
    assert_eq!(offset_of!(KeyStatsC, has_expiry), 40);
    assert_eq!(offset_of!(KeyStatsC, expires_at_unix_us), 48);

    // sia_host_query_t
    assert_eq!(size_of::<HostQueryC>(), 48, "sia_host_query_t");
    assert_eq!(align_of::<HostQueryC>(), 8, "sia_host_query_t");
    assert_eq!(offset_of!(HostQueryC, has_location), 0);
    assert_eq!(offset_of!(HostQueryC, latitude), 8);
    assert_eq!(offset_of!(HostQueryC, longitude), 16);
    assert_eq!(offset_of!(HostQueryC, offset), 24);
    assert_eq!(offset_of!(HostQueryC, limit), 32);
    assert_eq!(offset_of!(HostQueryC, country), 40);

    // A NULL callback must be the all-zero pattern a zeroed C struct has.
    let zeroed: UploadOptionsC = unsafe { std::mem::zeroed() };
    assert!(zeroed.on_shard.is_none(), "NULL must read as no callback");
}

/// The pipe only breaks once the upload task has ended, so the write reports
/// what actually stopped the upload rather than the broken pipe. Five hosts
/// cannot satisfy the default ten of thirty, so the task fails on the first
/// slab and the writer finds the read half gone.
#[test]
fn a_failed_upload_reports_its_own_error_through_the_write() {
    unsafe {
        let mock = sia_mock_new(5);
        let seed = [41u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut up = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_upload_start(
                sdk,
                std::ptr::null(),
                &raw const opts,
                &raw mut up,
                &raw mut err
            ),
            SIA_OK,
            "sia_upload_start: {}",
            take_err(err)
        );

        // Keep writing until the task's failure reaches the writer. The pipe
        // buffers, so the first writes land before the break shows up.
        let chunk = vec![7u8; 1 << 20];
        let mut code = SIA_OK;
        let mut message = String::new();
        for _ in 0..80 {
            let mut err = std::ptr::null_mut();
            let mut wrote = 0usize;
            code = sia_upload_write(
                up,
                chunk.as_ptr(),
                chunk.len(),
                std::ptr::null_mut(),
                &raw mut wrote,
                &raw mut err,
            );
            if code != SIA_OK {
                message = take_err(err);
                break;
            }
        }

        assert_ne!(code, SIA_OK, "an upload with five hosts must not succeed");
        assert_ne!(
            code, SIA_ERR_CANCELLED,
            "nothing cancelled this write: {message}"
        );
        // On the message rather than the status because the queue's
        // "not enough hosts to start" has no code of its own. It is still
        // what proves the task's error crossed, not the broken pipe.
        assert!(
            message.contains("not enough initial hosts"),
            "the write must carry the upload's own error, got {message:?}"
        );

        sia_upload_free(up);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// Starting an add on a finalized upload is refused by the call that made the
/// mistake, rather than accepted and failed later by add_write or add_finish.
#[test]
fn add_begin_after_finalize_is_refused() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [53u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(
                packed,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_OK,
            "finalize: {}",
            take_err(err)
        );
        sia_object_array_free(objs, len);

        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_add_begin(packed, &raw mut err),
            SIA_ERR_INVALID_STATE,
            "add_begin must refuse a finalized upload"
        );
        let message = take_err(err);
        assert!(
            message.contains("finalized"),
            "the refusal must say why, got {message:?}"
        );

        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}

/// A cancelled finalize consumes the upload however far it got, so the caller
/// is not left guessing whether a retry resumes it or reports it gone.
#[test]
fn cancelled_finalize_consumes_the_upload() {
    unsafe {
        let mock = sia_mock_new(40);
        let seed = [67u8; 32];
        let mut sdk = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_mock_sdk(
                mock,
                seed.as_ptr(),
                std::ptr::null_mut(),
                &raw mut sdk,
                &raw mut err
            ),
            SIA_OK,
            "sia_mock_sdk: {}",
            take_err(err)
        );

        let opts = default_upload_options();
        let mut packed = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_start(sdk, &raw const opts, &raw mut packed, &raw mut err),
            SIA_OK,
            "sia_packed_upload_start: {}",
            take_err(err)
        );

        let cancel = sia_cancel_new();
        sia_cancel_cancel(cancel);
        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(packed, cancel, &raw mut objs, &raw mut len, &raw mut err),
            SIA_ERR_CANCELLED,
            "a cancelled finalize: {}",
            take_err(err)
        );
        sia_cancel_free(cancel);

        let mut objs = std::ptr::null_mut();
        let mut len = 0usize;
        let mut err = std::ptr::null_mut();
        assert_eq!(
            sia_packed_upload_finalize(
                packed,
                std::ptr::null_mut(),
                &raw mut objs,
                &raw mut len,
                &raw mut err
            ),
            SIA_ERR_INVALID_STATE,
            "the upload is gone, so a retry must say so rather than succeed"
        );
        let message = take_err(err);
        assert!(
            message.contains("finalized"),
            "the refusal must say why, got {message:?}"
        );

        sia_packed_upload_free(packed);
        sia_sdk_free(sdk);
        sia_mock_free(mock);
    }
}
