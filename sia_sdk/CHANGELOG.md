## 0.2.0 (2026-01-28)

### Breaking Changes

- Changes the Seed constructor to accept a mnemonic instead of raw entropy and adds `Seed::from_seed` to replace the old constructor.
- Merge SlabSlice and Slab types.

### Features

- Added signature macro for testing.

### Fixes

- Fix release registry
- Make use of goodForUpload field

## 0.1.3 (2025-10-04)

### Features

- Add JSON serialization to ChainState

### Fixes

- Fixed release workflow.

## 0.1.2 (2025-10-04)

### Features

- Add JSON serialization to ChainState

### Fixes

- Fix path dependency versions.

## 0.1.1 (2025-10-04)

### Features

- Add JSON serialization to ChainState

## 0.1.0 (2025-10-04)

### Breaking Changes

- Change signing code to borrow.

### Features

- Add JSON serialization to ChainState
- Add account API endpoint to app_client and FFI implementation.
- Add generic support for reading and writing erasure-coded slabs.
- Add method to generate object URLs.
- Add object methods to FFI crate.
- Add pin_slab and unpin_slab to FFI.
- Add an SDK client that exposes an upload and download method.
- Add slab downloader.
- Add support for encrypting and decrypting shards.
- Add support for ReedSolomon erasure coding.
- Added AsyncSiaEncodable and AsyncSiaDecodable traits.
- Added object uploading.
- Added RHP4 request and response types.
- Added RHP4 RPC usage and helpers.
- Implement client-side encryption for quic uploads and downloads.
- Support download range requests.
- Use randomly generated encryption keys.
- Verify proofs in RPCWriteSector and RPCReadSector.

### Fixes

- Add V2 host announcement support.
- Fixed RPC write sector encoding.
- Swap out 'time' dependency for 'chrono'.
- Use PublicKey for account key type.

## 0.0.2 (2025-07-21)

### Features

- Add JSON serialization to ChainState
- Add ID derivation helpers to transactions, blocks, and siafund claims
- v2 signing implemented

#### Refactor V1 transaction signing

Replaced `v1::Transaction::sign` with `v1::Transaction::whole_sig_hash` and `v1::Transaction::partial_sig_hash`. This change is primarily to provide a more consistent experience with `core` and the V2::Transaction API.

### Fixes

- Fix element accumulator encoding
