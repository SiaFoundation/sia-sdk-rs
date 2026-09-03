## 0.10.0 (2026-09-03)

### Breaking Changes

- Remove contextual fields from several error variants to reduce `Error` enum size.

#### Renamed the share URL methods on `Sdk`.

`Sdk::share_object` and `Sdk::shared_object` are now `Sdk::object_share_url` and `Sdk::object_from_share_url`. The bindings change to match, so `shareObject` and `sharedObject` become `objectShareUrl` and `objectFromShareUrl`.

### Features

#### Added `connect_pre_authorized` for connecting with a pre-authorized key.

Applications can now bypass the interactive approval flow by connecting with a pre-authorized key that the indexer operator provisions out of band. `Builder::connect_pre_authorized(pre_authorized_key, mnemonic)` performs the connect, approval, and registration steps in one call and returns a ready SDK. The method is also exposed through the ffi, napi, and wasm bindings.

#### Added `reconnecting` to the connection approval flow.

After approval, `reconnecting()` reports whether the connect key already has an account for the application. When reconnecting, `register` and `connect_pre_authorized` fail with `WrongRecoveryPhrase` if the recovery phrase does not match the existing account.

### Fixes

- Added the HTTP status code to `AppApiError::Api` and removed the `Unauthorized` and `NotFound` variants
- Increased default API timeout for slow indexers.
- Retry failed shards up to three times before failing the download.
- Added a method for truncating objects.

## 0.9.0 (2026-08-07)

### Breaking Changes

- Add a version field to slabs.
- Added `PackedUploadoptions` for packed uploads.

### Features

- Encrypt object data per slab so each slab can be re-encrypted independently without reusing the object's data key.
- Switch sector root and range proof verifier to optimized SIMD backends.

#### Added path-based uploads behind the `fs` feature.

`Sdk::upload_path` and `PackedUpload::add_path` open a file and read it to EOF, so callers uploading from disk no longer stream every chunk across the language boundary. The feature is unavailable on wasm32; the FFI and Node bindings enable it and expose `uploadPath`/`addPath`.

#### Added `start_offset` to `UploadOptions`.

This allows objects to be rewritten without reuploading the entire object. The original object is not replaced, so both versions can be pinned simultaneously.

#### Uploads will no longer block indefinitely until completion.

Removed the progressive upload timeout and hosts are now retried a maximum of 3 times before giving up. The default 
timeout is now 1.5m per shard per attempt. This should give enough time on slow connections. Racing and prioritization
will still prioritize faster hosts after warming up.

Users can still manually timeout

### Fixes

#### Reject malformed share-link encryption keys.

The error for a bad share-link key now states it must be base64url-encoded rather than hex (the fragment was already decoded as base64url), and a fragment that does not decode to exactly 32 bytes is rejected instead of being silently zero-padded into a bogus key.

## 0.8.0 (2026-06-23)

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

## 0.7.2 (2026-05-18)

### Fixes

- Bump sia_core_derive.

## 0.7.1 (2026-05-18)

### Fixes

- Update `sia_core` to `0.3.1`.

## 0.7.0 (2026-04-27)

### Breaking Changes

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

#### Emit NAPI type definitions

Enable the `type-def` feature on `napi-derive` and add `ts_args_type` on `set_logger` so `napi build --dts` produces a usable `index.d.ts`.

## 0.6.0 (2026-04-18)

### Breaking Changes

- Initialize nodejs bindings
- Replaced upload/download progress channels with more detailed callbacks.

### Fixes

- Removed hardcoded 1s timeout for RPC settings when writing and reading sectors
