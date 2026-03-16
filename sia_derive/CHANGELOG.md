## 0.0.7 (2026-03-16)

### Features

- Introduce mux crate and frame module

### Fixes

- use AsyncRead/AsyncWrite traits instead of Ext variants in trait bounds

#### Check if we have enough hosts prior to encoding in upload_slabs

##261 by @Alrighttt

Fixes https://github.com/SiaFoundation/sia-sdk-rs/issues/251

- Added an `available_for_upload` method that returns the amount of known hosts marked `good_for_upload`.
- Added a check in `upload_slabs` that verifies we have enough good hosts prior to encoding any data. 
- Adds a variant to `QueueError` for `upload_slabs`'s new failure case. This enables testing for this new case specifically.

#### Go SDK test parity

##266 by @Alrighttt

This pull requests adds some missing test cases that exist within the Go SDK. Closes https://github.com/SiaFoundation/sia-sdk-rs/issues/220

The remaining tests that have not been ported require changes to the `SDK` struct to allow mocking the `api_client`. I will work on a solution for this.

## 0.0.6 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.0.5 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.0.4 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.0.3 (2025-10-04)

### Features

- Add JSON serialization to ChainState
- Add account API endpoint to app_client and FFI implementation.
- Add pin_slab and unpin_slab to FFI.
- Added AsyncSiaEncodable and AsyncSiaDecodable traits.
- Use randomly generated encryption keys.

### Fixes

- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.

## 0.0.2 (2025-07-21)

### Features

- Add JSON serialization to ChainState
