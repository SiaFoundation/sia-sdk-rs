---
sia_mux: minor
---

# Update ed25519-dalek and x25519-dalek to 3.0

`dial`, `accept`, and their `_with_settings` variants now take ed25519-dalek 3.0 `SigningKey` and `VerifyingKey` values, and `HandshakeError::InvalidSignature` carries the 3.0 `SignatureError`. Callers still on ed25519-dalek 2.x need to upgrade alongside.
