---
sia_core: major
sia_storage: minor
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Negotiate CBOR responses from the indexer

The SDK prefers CBOR responses from the indexer and decodes them according to their content type, with JSON fallback for older indexers. Set `Builder::with_cbor(false)` or connect with `SharedSdk::connect_with_cbor(url, seed, false)` to request JSON for easier inspection; the FFI, N-API, and WASM bindings expose the same `withCbor` builder method and `connectWithCbor` constructor. Request bodies remain JSON. Malformed CBOR responses return the new `AppApiError::Cbor` variant.

`PublicKey`, `Signature`, and the types defined with `impl_hash_id!` (`Hash256`, `BlockID`, `TransactionID`, and the other IDs) now serialize as byte strings in non-human-readable formats instead of strings or fixed-size tuples, as do `sia_storage`'s `EncryptionKey` and the encrypted keys and metadata of a `SealedObject`.

Null timestamps from the indexer decode as Go's zero time and null lists as empty lists. `sia_core::types::null_as_zero_time` provides the timestamp decoding.
