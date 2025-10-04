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

#### Add method for pinning multiple slabs

After https://github.com/SiaFoundation/indexd/pull/427 is merged, we will need to send an array of SlabPinParams to the pin slabs endpoint.  This PR makes the changes needed for that and also adds in helpers that preserve the old `pin_slab` functionality.

### Fixes

- Enable replacing log hook.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.
