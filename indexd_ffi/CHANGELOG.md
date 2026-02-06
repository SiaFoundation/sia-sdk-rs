## 0.3.1 (2026-02-06)

### Fixes

- Fix slab length in packed object
- Progress callback will now be called as expected for packed uploads.

#### Check if we have enough hosts prior to encoding in upload_slabs

##261 by @Alrighttt

Fixes https://github.com/SiaFoundation/sia-sdk-rs/issues/251

- Added an `available_for_upload` method that returns the amount of known hosts marked `good_for_upload`.
- Added a check in `upload_slabs` that verifies we have enough good hosts prior to encoding any data. 
- Adds a variant to `QueueError` for `upload_slabs`'s new failure case. This enables testing for this new case specifically.

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
