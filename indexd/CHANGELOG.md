## 0.2.0 (2025-11-12)

### Breaking Changes

- Reduced size of signed urls by shortening query parameter names and using base64 URL encoding instead of hex.

### Features

- Add optional host filters (offset/limit/service-account/protocol/country) plus distance sort
- Exposed `Hosts` struct to deduplicate host selection and performance tracking for scenarios that can not use the QUIC client.
- Track RPC failure rate when selecting hosts rather than raw RPCs.

### Fixes

- Fix decoding failing when encrypted metadata is null or missing
- Fixed an issue with uploads stalling after resuming on some platforms.
- Fixed signing when URLs have port number.
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
