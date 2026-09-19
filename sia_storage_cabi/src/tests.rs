use crate::abi::*;
use crate::download::*;
use crate::mock::*;
use crate::object::*;
use crate::sdk::*;
use crate::sharing::*;
use crate::upload::*;
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
                break take_err(err);
            }
            assert_ne!(n, 0, "download reported a clean EOF after sector loss");
        };
        sia_download_free(dl);

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
