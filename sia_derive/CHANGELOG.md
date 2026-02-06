## 0.0.7 (2026-02-06)

### Fixes

#### Check if we have enough hosts prior to encoding in upload_slabs

##261 by @Alrighttt

Fixes https://github.com/SiaFoundation/sia-sdk-rs/issues/251

- Added an `available_for_upload` method that returns the amount of known hosts marked `good_for_upload`.
- Added a check in `upload_slabs` that verifies we have enough good hosts prior to encoding any data. 
- Adds a variant to `QueueError` for `upload_slabs`'s new failure case. This enables testing for this new case specifically.

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
