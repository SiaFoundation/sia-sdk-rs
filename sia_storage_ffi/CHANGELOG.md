## 0.6.0 (2026-04-06)

### Breaking Changes

#### Resumable uploads

`SDK::upload` now takes an `Object` parameter and appends uploaded slabs to it. This enables resumable uploads by passing the same object back to `upload` with a new reader.

For new uploads, pass `Object::default()` (Rust) or `PinnedObject::new()` (FFI). This is a breaking change to the upload API signature.

## 0.5.1 (2026-04-05)

### Features

- Download objects in chunks to improve streaming.

#### Replace PrivateKey with AppKey in public API

Replaced all uses of `PrivateKey` in the public API with `AppKey`. `PrivateKey` is no longer re-exported.

Added `UploadOptions::validate` to check erasure coding parameters for sufficient durability.

Made internal `app_client::Client` methods `pub(crate)` and moved data types (`App`, `Account`, `GeoLocation`, `HostQuery`, `ObjectsCursor`) to `lib.rs`.

Added doc strings to all public items.

### Fixes

- Simplified FFI reader and writer by polling the future instead of passing through channels and a background task.
- Update account types

## 0.5.0 (2026-03-23)

### Breaking Changes

- Renamed crate to `sia_storage_ffi`

## 0.4.0 (2026-03-18)

### Breaking Changes

- Added ephemeral key to authorization flow

### Features

- Added `ready` field to account.

## 0.3.1 (2026-03-16)

### Features

- Introduce mux crate and frame module
- Return `sia://` links from the indexd SDK.

### Fixes

- use AsyncRead/AsyncWrite traits instead of Ext variants in trait bounds
- Added cancel function to cancel inflight packed uploads.
- Fix slab length in packed object
- Improved parallelism of packed uploads.
- Progress callback will now be called as expected for packed uploads.

#### Check if we have enough hosts prior to encoding in upload_slabs

##261 by @Alrighttt

Fixes https://github.com/SiaFoundation/sia-sdk-rs/issues/251

- Added an `available_for_upload` method that returns the amount of known hosts marked `good_for_upload`.
- Added a check in `upload_slabs` that verifies we have enough good hosts prior to encoding any data. 
- Adds a variant to `QueueError` for `upload_slabs`'s new failure case. This enables testing for this new case specifically.

#### Go SDK test parity

##266 by @Alrighttt

This pull requests adds some missing test cases that exist within the Go SDK. Closes https://github.com/SiaFoundation/sia-sdk-rs/issues/220

The remaining tests that have not been ported require changes to the `SDK` struct to allow mocking the `api_client`. I will work on a solution for this.

## 0.3.0 (2026-01-28)

### Breaking Changes

- Implemented new `indexd` authentication.
- Merge SlabSlice and Slab types.
- Reduced size of shared object URLs by using base64 URL encoding for the encryption key.
- Reduced size of signed urls by shortening query parameter names and using base64 URL encoding instead of hex.
- Renamed `key` to `id` in object event and cursor.

### Features

- Add optional host filters (offset/limit/service-account/protocol/country) plus distance sort
- Fixed an issue with downloaded data not always being flushed to the passed in writer.
- Implement upload packing
- Track RPC failure rate when selecting hosts rather than raw RPCs.
- Unified the SDK logic where possible.

### Fixes

- Added missing updated_at field.
- Fix decoding failing when encrypted metadata is null or missing
- Fixed an issue with uploads stalling after resuming on some platforms.
- Fixed progress callback not being called immediately leading to incorrect reporting.
- Fixed signing when URLs have port number.
- Improved upload performance by 75%.
- Make use of goodForUpload field
- Remove service account fields
- Update object listing endpoints to use events

## 0.2.2 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.2.1 (2025-10-04)

### Features

- Add JSON serialization to ChainState

### Fixes

- Fix path dependency versions.

## 0.2.0 (2025-10-04)

### Breaking Changes

- Publish to cargo

### Features

- Add JSON serialization to ChainState

## 0.1.1 (2025-10-04)

### Features

- Add JSON serialization to ChainState
- Add account API endpoint to app_client and FFI implementation.
- Add object sharing.
- Add pin_slab and unpin_slab to FFI.
- Add progress callback.
- Add slab metadata to SDK
- Add slab pruning
- Remove separate range methods.
- Use randomly generated encryption keys.
- Add method for pinning multiple slabs

### Fixes

- Enable replacing log hook.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.
