---
sia_core: major
---

# Serialize keys and IDs as byte strings in non-human-readable formats

`PublicKey`, `Signature`, and the types defined with `impl_hash_id!` (`Hash256`, `BlockID`, `TransactionID`, and the other IDs) now serialize as byte strings in non-human-readable formats such as CBOR instead of strings or fixed-size tuples, and deserialize from either form. JSON output is unchanged. `sia_core::types::deserialize_str_or_bytes` is available for types that follow the same convention.

`AccountToken::valid_until` decodes a null timestamp as Go's zero time, since indexd's CBOR encoder writes the zero `time.Time` as null. `sia_core::types::null_as_zero_time` provides the same decoding for other timestamps.
