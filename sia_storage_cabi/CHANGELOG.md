## 0.1.4 (2026-11-09)

### Features

#### Add `sia_sdk_object_event_summaries` to C ABI

Each event's summary is read with `sia_event_summaries_at` and its metadata with `sia_event_summaries_metadata`. It pages with the same cursor as `sia_sdk_object_events`.

#### Add `Sdk::shared_object_summaries`, which lists the objects attached to one of the account's sharing keys without their slabs

It returns the same `ObjectSummary` as `SharedSdk::object_summaries`, with each object's id, size, decrypted metadata and timestamps, so an owner can show what a key shares without fetching every object's slabs. The WASM and NAPI bindings expose it as `sharedObjectSummaries`, the FFI binding as `shared_object_summaries`, and the C ABI as `sia_sdk_shared_object_summaries`, which is read with the existing `sia_object_summaries_*` functions.

### Fixes

#### Keep browser uploads moving when some hosts do not answer

In the browser, uploads stalled for minutes when some hosts never answered a WebTransport handshake. Uploads tried new hosts before ones they had measured, and in Chrome each handshake that never completes delays the next. Uploads and downloads on every platform now rank a measured host above an untried one with the same failure rate.

## 0.1.3 (2026-10-28)

### Features

- Added `PreAuthorizedKey` helpers for random key generation, seed import/export, and signing indexer creation requests.

## 0.1.2 (2026-10-27)

### Features

- Host performance metrics and the price cache are now shared across all SDK instances.

### Fixes

- Appending data now efficiently repacks the last slab when it is not full.
- Fixed an Android crash on the first HTTPS request in apps that load React Native.

## 0.1.1 (2026-10-21)

### Features

- Added a C ABI for the storage SDK.

### Fixes

#### Upgrade reqwest and update TLS security dependencies

Upgrade reqwest to 0.13.5, using platform certificate verification on native platforms except Android. Android uses a preconfigured Rustls client with bundled roots to avoid requiring JNI initialization. Browser builds continue using browser TLS.

Update `webpki-roots` to 1.0.10 and `rustls-webpki` to 0.103.16 in the lockfile to address RUSTSEC-2026-0381 and RUSTSEC-2026-0382.
