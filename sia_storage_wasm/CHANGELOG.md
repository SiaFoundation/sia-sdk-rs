## 0.4.0 (2026-06-23)

### Breaking Changes

#### Added adaptive transfer concurrency

Uploads and downloads no longer take a fixed `max_inflight` concurrency limit — concurrency now adapts to network conditions automatically. Memory use is bounded directly instead, by two new options: `UploadOptions::max_buffered_slabs` and `DownloadOptions::max_buffered_chunks`, each defaulting to roughly 10% of system memory when unset. The `max_inflight` field is removed from the upload, download, and language-binding option types.

### Features

- Changed download chunking to ramp up to reduce round trips on large downloads.
- Overprovision shard downloads to reduce tail latency from slow hosts

### Fixes

- Fix memory leak in WASM download method
- Removed rayon dependency due to panics at high concurrency

#### Made racing adaptive so that racers will not steal slots from higher priority work

For uploads, racing will only start when every shard has an attempt in flight. For downloads, racing will only start when the chunk is near the read head. The race timeout is derived from the p95 of recently completed RPCs instead of a fixed interval so only hosts well outside the normal latency spread get raced.

## 0.3.2 (2026-05-18)

### Fixes

- Bump sia_core_derive.

## 0.3.1 (2026-05-18)

### Fixes

- Update `sia_core` to `0.3.1`.

## 0.3.0 (2026-04-27)

### Breaking Changes

- setLogger now matches the NAPI callback.

#### Rename `slab_size` to `optimal_data_size` where it refers to the data-only portion

Methods and fields that previously returned or stored `data_shards * SECTOR_SIZE` (the packing period for `PackedUpload`) are now named `optimal_data_size` to distinguish them from the true encoded slab size (`total_shards * SECTOR_SIZE`, which remains `slab_size`). Affects `PackedUpload::slab_size()` (Rust, FFI, NAPI) and the `slabSize` JS getter (now `optimalDataSize`).

`UploadOptions::slab_size()`, `UploadOptions::optimal_data_size()`, `PackedUpload::optimal_data_size()`, and `PackedUpload::slabs()` now return `usize` instead of `u64`.

### Features

- `upload_packed` now returns a `Result` and will error if invalid options are passed to it.

#### `PackedUpload` stays usable after a reader error

If the reader passed to `add` errored mid-stream, bytes it had already buffered were silently attributed to the next object, corrupting it. Partial reads now become dead padding in the slab and subsequent objects stay aligned.

### Fixes

- Fix ReadableStream usage on Safari.
- wasm: read struct params via js_sys::Reflect

#### Simplify `PackedUpload` binding internals

Replaced the per-upload mpsc actor with a mutex and a cancellation token. Errors from `add` and `finalize` now propagate directly instead of through a oneshot that could swallow them, and no background task is kept per upload.

`cancel` is now sync (`fn cancel(&self)`) on the FFI and NAPI bindings, dropping the `async` and `Result` return — flipping a token and aborting in-flight tasks is fast and cannot fail. WASM was already sync.

## 0.2.0 (2026-04-18)

### Breaking Changes

- init sia_storage_wasm crate
- Replaced upload/download progress channels with more detailed callbacks.

### Fixes

- Removed hardcoded 1s timeout for RPC settings when writing and reading sectors
