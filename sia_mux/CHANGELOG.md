## 0.1.3 (2026-08-21)

### Fixes

#### Fix clippy lints introduced by Rust 1.98.

Rust 1.98 extended `clippy::result_large_err` to `impl Future` return positions, added `clippy::chunks_exact_to_as_chunks`, and tightened unused import detection. These are lint fixes only, with no behavior changes.

## 0.1.2 (2026-08-07)

### Features

#### Update ed25519-dalek and x25519-dalek to 3.0

`dial`, `accept`, and their `_with_settings` variants now take ed25519-dalek 3.0 `SigningKey` and `VerifyingKey` values, and `HandshakeError::InvalidSignature` carries the 3.0 `SignatureError`. Callers still on ed25519-dalek 2.x need to upgrade alongside.

## 0.1.1 (2026-06-23)

### Fixes

- Don't send FLAG_LAST if stream was not established

## 0.1.0 (2026-03-23)

### Breaking Changes

- Renamed crate to `sia_mux`
