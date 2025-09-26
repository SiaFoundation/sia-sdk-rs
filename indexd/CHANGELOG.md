## 0.0.2 (2025-09-26)

### Features

- Add JSON serialization to ChainState
- Add account API endpoint to app_client and FFI implementation.
- Add objects API to SDK and app client.
- Add pin_slab and unpin_slab to FFI.
- Add progress callback.
- Encrypt object metadata.
- Remove separate range methods.
- Use randomly generated encryption keys.
- Validate object key when fetching objects from indexd.

### Fixes

- Make upload progress more responsive.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.
