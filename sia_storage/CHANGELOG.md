## 0.6.0 (2026-04-06)

### Breaking Changes

#### Resumable uploads

`SDK::upload` now takes an `Object` parameter and appends uploaded slabs to it. This enables resumable uploads by passing the same object back to `upload` with a new reader.

For new uploads, pass `Object::default()` (Rust) or `PinnedObject::new()` (FFI). This is a breaking change to the upload API signature.

## 0.5.1 (2026-04-05)

### Features

- Add WebTransport client for WASM target
- Allow wasm32-unknown-unknown compilation
- Download objects in chunks to improve streaming.
- Fixes wasm32 compat framework compilation

#### Replace PrivateKey with AppKey in public API

Replaced all uses of `PrivateKey` in the public API with `AppKey`. `PrivateKey` is no longer re-exported.

Added `UploadOptions::validate` to check erasure coding parameters for sufficient durability.

Made internal `app_client::Client` methods `pub(crate)` and moved data types (`App`, `Account`, `GeoLocation`, `HostQuery`, `ObjectsCursor`) to `lib.rs`.

Added doc strings to all public items.

### Fixes

- Remove dyn dispatch of RHP client type
- Update account types

## 0.5.0 (2026-03-23)

### Breaking Changes

- Renamed crate to `sia_storage`

## 0.4.0 (2026-03-18)

### Breaking Changes

- Added ephemeral key to authorization flow
- Reduced the size of the pin object request. Up to 4TB of data can now be pinned in a single object.

### Features

- Added `ready` field to account.

## 0.3.0 (2026-03-16)

### Breaking Changes

- Re-export 3rd-party types to improve ergonomics.
- Use rustls-platform-verifier by default to simplify SDK initialization.

### Features

- Added mnemonic helpers.
- Introduce mux crate and frame module
- Return `sia://` links from the indexd SDK.

### Fixes

- use AsyncRead/AsyncWrite traits instead of Ext variants in trait bounds
- Added cancel function to cancel inflight packed uploads.

#### Check if we have enough hosts prior to encoding in upload_slabs

##261 by @Alrighttt

Fixes https://github.com/SiaFoundation/sia-sdk-rs/issues/251

- Added an `available_for_upload` method that returns the amount of known hosts marked `good_for_upload`.
- Added a check in `upload_slabs` that verifies we have enough good hosts prior to encoding any data. 
- Adds a variant to `QueueError` for `upload_slabs`'s new failure case. This enables testing for this new case specifically.

#### Fix upload racing race conditon

##258 by @Alrighttt

This fixes a race condition in the upload logic that could happen when the amount of healthy hosts is nearly the same as the amount of shards. This could happen when the racing mechanism was triggered prior to all of the initial shards being assigned a host. The slow hosts would be consumed from the HostQueue without completing the upload. This would cause a latter shard to hit a QueueError::NoMoreHosts error.

This changes the upload behavior so that each shard has a host assigned before any upload begins.

A `set_slow_hosts` method was added to the `MockRHP4Client` to allow easily testing these conditions. This mimics a similar mechanism from the Go SDK.

#### Go SDK test parity

##266 by @Alrighttt

This pull requests adds some missing test cases that exist within the Go SDK. Closes https://github.com/SiaFoundation/sia-sdk-rs/issues/220

The remaining tests that have not been ported require changes to the `SDK` struct to allow mocking the `api_client`. I will work on a solution for this.

## 0.2.0 (2026-01-28)

### Breaking Changes

- Added missing SDK functionality.
- Changed download function to borrow the writer.
- Implemented new `indexd` authentication.
- Merge SlabSlice and Slab types.
- Reduced size of signed urls by shortening query parameter names and using base64 URL encoding instead of hex.
- Renamed `key` to `id` in object event and cursor.

### Features

- Add optional host filters (offset/limit/service-account/protocol/country) plus distance sort
- Exposed `Hosts` struct to deduplicate host selection and performance tracking for scenarios that can not use the QUIC client.
- Implement upload packing
- Track RPC failure rate when selecting hosts rather than raw RPCs.
- Update the insufficient shard check in download_slab_shards.

### Fixes

- Fix decoding failing when encrypted metadata is null or missing
- Fixed an issue with uploads stalling after resuming on some platforms.
- Fixed progress callback not being called immediately leading to incorrect reporting.
- Fixed signing when URLs have port number.
- Improved upload performance by 75%.
- Make use of goodForUpload field
- Refactor the uploader and downloader to be transport agnostic to make it easier to add regression testing and benchmarks.
- Remove service account fields
- Remove SlabFetcher now that we have the full slab info in the object.
- Update object listing endpoints to use events

## 0.1.2 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.1.1 (2025-10-04)

### Features

- Add JSON serialization to ChainState

### Fixes

- Fix path dependency versions.

## 0.1.0 (2025-10-04)

### Breaking Changes

- Publish to cargo

### Features

- Add JSON serialization to ChainState

## 0.0.2 (2025-10-04)

### Features

- Add JSON serialization to ChainState
- Add account API endpoint to app_client and FFI implementation.
- Add objects API to SDK and app client.
- Add pin_slab and unpin_slab to FFI.
- Add progress callback.
- Add slab pruning
- Encrypt object metadata.
- Remove separate range methods.
- Use randomly generated encryption keys.
- Validate object key when fetching objects from indexd.
- Add method for pinning multiple slabs

### Fixes

- Make upload progress more responsive.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.
