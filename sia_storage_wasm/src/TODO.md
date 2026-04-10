# sia_storage_wasm — Binding Status

## Types

| `sia_storage` type | `sia_storage_wasm` | Status |
|---|---|---|
| `SDK` | `StorageSdk` | Done — opaque handle |
| `Builder<S>` | `SdkBuilder` | Done — state machine flattened |
| `Object` | `PinnedObject` | Done — opaque handle with id/size/metadata/info methods |
| `SealedObject` | — | **Missing** — needed for seal/open (offline storage) |
| `UploadOptions` | `UploadOptions` | Done — wraps `sia_storage::UploadOptions`, optional param on `upload()` |
| `DownloadOptions` | `DownloadOptions` | Done — wraps `sia_storage::DownloadOptions`, optional param on `download()`/`download_object()` |
| `PackedUpload` | — | **Missing** — streaming multi-object upload |
| `PinnedSlab` | — | **Missing** — returned by `slab()` |
| `Slab` | — | **Missing** — inside Object, not exposed |
| `Sector` | — | **Missing** — inside Slab, not exposed |
| `EncryptionKey` | — | **Missing** — inside Object/Slab, not exposed |
| `Account` | `AccountInfo` (serde) | Done — serialized as plain JS object |
| `Host` | `HostInfo` (serde) | Done — serialized as plain JS object |
| `ObjectEvent` | `ObjectEventInfo` (serde) | Done — serialized as plain JS object |
| `ObjectsCursor` | inline params | Done — passed as separate params |
| `AppMetadata` | inline params | Done — passed as constructor params |
| `HostQuery` | `HostQuery` | Done — wraps `sia_storage::HostQuery`, optional param on `hosts()` |
| `GeoLocation` | — | Not needed — included inside HostInfo |
| `App` | — | Not needed — flattened into AccountInfo |

## SDK Methods

| `sia_storage` method | `sia_storage_wasm` | Status |
|---|---|---|
| `app_key()` | `app_key()` | Done |
| `upload()` | `upload()` | Done |
| `upload_packed()` | — | **Missing** |
| `download()` | `download()` + `download_object()` | Done — by ID or by handle |
| `hosts()` | `hosts()` | Done |
| `account()` | `account()` | Done |
| `object()` | `object()` | Done (returns serialized info) |
| `object_events()` | `object_events()` | Done |
| `prune_slabs()` | `prune_slabs()` | Done |
| `update_object_metadata()` | `update_object_metadata()` | Done — accepts `&PinnedObject` |
| `delete_object()` | `delete_object()` | Done |
| `share_object()` | — | **Missing** — needs `valid_until` param + returns URL |
| `shared_object()` | — | **Missing** |
| `pin_object()` | `pin_object()` | Done — accepts `&PinnedObject` |
| `slab()` | — | **Missing** |
| `generate_recovery_phrase()` | `generate_recovery_phrase()` | Done |
| `validate_recovery_phrase()` | `validate_recovery_phrase()` | Done |

## Priority

### Needed to unblock remaining SDK methods
1. ~~**`Object` opaque handle**~~ — Done as `PinnedObject`.
2. ~~**`UploadOptions`**~~ — Done. Optional param on `upload()`.
3. ~~**`DownloadOptions`**~~ — Done. Optional param on `download()`/`download_object()`.
4. **`share_object()`** — needs `valid_until` timestamp param, returns URL string.
5. **`shared_object()`** — fetch object by share URL.

### Nice-to-have
4. `SealedObject` — for offline storage/transmission of object metadata.
5. `PackedUpload` — multi-object packed upload for small files.
6. `PinnedSlab` / `Slab` / `Sector` — slab-level inspection.
7. `HostQuery` — filtered host queries (by location, etc.).

### Streaming API (required for large files)

The current `upload(Vec<u8>)` and `download() -> Vec<u8>` require the entire file
in WASM linear memory. This limits practical file sizes to ~500 MiB before OOM
due to memory fragmentation (input buffer + shard buffers during erasure coding).

**Streaming upload** — JS pushes chunks incrementally via a channel:
```rust
#[wasm_bindgen]
pub struct StreamingUpload { ... }
impl StreamingUpload {
    pub fn push_chunk(&self, data: Vec<u8>) -> js_sys::Promise;
    pub fn finish(&self) -> js_sys::Promise; // returns Object handle
}
```
The SDK's `upload()` already takes `impl AsyncRead` — needs an `AsyncRead`
adapter backed by a `tokio::sync::mpsc` channel fed by `push_chunk`.
Reference: `indexd_wasm`'s `StreamingUpload` / `pushChunk()` on `matt/wasm-syncer`.

**Streaming download** — Rust pushes decoded chunks to a JS callback:
```rust
pub async fn download_streaming(
    &self, key_hex: &str, on_chunk: js_sys::Function
) -> Result<(), JsValue>;
```
Or return a `ReadableStream` that JS can pipe to disk via the File System Access API.

## Binding Strategy

Two patterns depending on whether JS needs to pass the value back to Rust:

- **Read-only data (JS consumes, never passes back)**: use `serde_wasm_bindgen::to_value` to serialize a `#[derive(Serialize)]` struct into a native JS object. No wrapper type needed. Examples: `AccountInfo`, `HostInfo`, `ObjectEventInfo`, `ObjectInfo`.

- **Opaque handles (JS holds a reference, passes back to Rust)**: use a `#[wasm_bindgen]` wrapper struct that owns the inner `sia_storage` type. JS gets an opaque pointer and calls methods on it. Required when the Rust value has internal state (encryption keys, slab data) that can't survive a serialize/deserialize round-trip. Examples: `Object`, `SealedObject`, `PackedUpload`.

## Code Cleanup

- ~~`upload()` hardcodes `max_inflight: 24`~~ — Done. Accepts optional `UploadOptions`.
- ~~`download()` / `download_object()` use `DownloadOptions::default()`~~ — Done. Accept optional `DownloadOptions`.
- `log::debug!()` calls in `upload()` — useful for development but noisy in production. Consider removing before merge or gating behind a feature flag.

## Notes

- `PinnedObject` opaque handle is implemented. `upload()` returns it, `pin_object()` / `download_object()` / `update_object_metadata()` accept it by reference.
- `wasm_bindgen` cannot export types from other crates. All wrapper types must live in `sia_storage_wasm`.
- For TypeScript type safety on serde-serialized values, hand-written `.d.ts` augmentations can declare the shape of the returned JS objects.
