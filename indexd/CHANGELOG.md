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
