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
