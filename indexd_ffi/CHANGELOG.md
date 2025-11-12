## 0.3.0 (2025-11-12)

### Breaking Changes

- Reduced size of shared object URLs by using base64 URL encoding for the encryption key.
- Reduced size of signed urls by shortening query parameter names and using base64 URL encoding instead of hex.

### Features

- Add optional host filters (offset/limit/service-account/protocol/country) plus distance sort
- Track RPC failure rate when selecting hosts rather than raw RPCs.

### Fixes

- Added missing updated_at field.
- Fix decoding failing when encrypted metadata is null or missing
- Fixed an issue with uploads stalling after resuming on some platforms.
- Fixed signing when URLs have port number.
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
