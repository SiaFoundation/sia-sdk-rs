## 0.10.0 (2026-07-22)

### Breaking Changes

- Add a version field to slabs.
- Added `PackedUploadoptions` for packed uploads.

### Features

- Encrypt object data per slab so each slab can be re-encrypted independently without reusing the object's data key.
- Switch sector root and range proof verifier to optimized SIMD backends.

#### Added `start_offset` to `UploadOptions`.

This allows objects to be rewritten without reuploading the entire object. The original object is not replaced, so both versions can be pinned simultaneously.

## 0.9.0 (2026-06-23)

### Breaking Changes

- Changed DownloadOptions::max_inflight from u8 to u32.

#### Added adaptive transfer concurrency

Uploads and downloads no longer take a fixed `max_inflight` concurrency limit — concurrency now adapts to network conditions automatically. Memory use is bounded directly instead, by two new options: `UploadOptions::max_buffered_slabs` and `DownloadOptions::max_buffered_chunks`, each defaulting to roughly 10% of system memory when unset. The `max_inflight` field is removed from the upload, download, and language-binding option types.

### Features

- Changed download chunking to ramp up to reduce round trips on large downloads.
- Overprovision shard downloads to reduce tail latency from slow hosts

### Fixes

- Removed rayon dependency due to panics at high concurrency

#### Made racing adaptive so that racers will not steal slots from higher priority work

For uploads, racing will only start when every shard has an attempt in flight. For downloads, racing will only start when the chunk is near the read head. The race timeout is derived from the p95 of recently completed RPCs instead of a fixed interval so only hosts well outside the normal latency spread get raced.

## 0.8.1 (2026-05-18)

### Fixes

- Bump sia_core_derive.

## 0.8.0 (2026-04-27)

### Breaking Changes

#### Rename `AppMeta` to `AppMetadata`

The uniffi struct accepted by `Builder::new` is now named `AppMetadata`, matching the Rust SDK and the WASM binding.

#### Rename `slab_size` to `optimal_data_size` where it refers to the data-only portion

Methods and fields that previously returned or stored `data_shards * SECTOR_SIZE` (the packing period for `PackedUpload`) are now named `optimal_data_size` to distinguish them from the true encoded slab size (`total_shards * SECTOR_SIZE`, which remains `slab_size`). Affects `PackedUpload::slab_size()` (Rust, FFI, NAPI) and the `slabSize` JS getter (now `optimalDataSize`).

`UploadOptions::slab_size()`, `UploadOptions::optimal_data_size()`, `PackedUpload::optimal_data_size()`, and `PackedUpload::slabs()` now return `usize` instead of `u64`.

#### Simplify `PackedUpload` binding internals

Replaced the per-upload mpsc actor with a mutex and a cancellation token. Errors from `add` and `finalize` now propagate directly instead of through a oneshot that could swallow them, and no background task is kept per upload.

`cancel` is now sync (`fn cancel(&self)`) on the FFI and NAPI bindings, dropping the `async` and `Result` return — flipping a token and aborting in-flight tasks is fast and cannot fail. WASM was already sync.

### Features

- `upload_packed` now returns a `Result` and will error if invalid options are passed to it.

#### `PackedUpload` stays usable after a reader error

If the reader passed to `add` errored mid-stream, bytes it had already buffered were silently attributed to the next object, corrupting it. Partial reads now become dead padding in the slab and subsequent objects stay aligned.

### Fixes

- Rename download close function

## 0.7.0 (2026-04-18)

### Breaking Changes

- Replaced upload/download progress channels with more detailed callbacks.

#### Download returns an AsyncRead

`SDK::download` now returns a `Download` handle implementing `AsyncRead`
instead of taking a writer. Callers pull data with `tokio::io::copy` or any
other `AsyncRead` consumer.

The `sia_storage_ffi` `SDK::download` now returns a `Download` object with
`read()` and `close()` methods instead of taking a foreign `Writer`. The
`Writer` foreign trait has been removed.

### Fixes

- Removed hardcoded 1s timeout for RPC settings when writing and reading sectors

## 0.6.1 (2026-04-06)

### Features

- Remove redundant FFI chunked download loop and delegate to the SDK directly.

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
