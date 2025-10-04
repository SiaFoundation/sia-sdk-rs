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

#### Add method for pinning multiple slabs

After https://github.com/SiaFoundation/indexd/pull/427 is merged, we will need to send an array of SlabPinParams to the pin slabs endpoint.  This PR makes the changes needed for that and also adds in helpers that preserve the old `pin_slab` functionality.

### Fixes

- Make upload progress more responsive.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.
