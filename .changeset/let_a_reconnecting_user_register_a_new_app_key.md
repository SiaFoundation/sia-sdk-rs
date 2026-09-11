---
sia_storage_napi: major
sia_storage_wasm: major
sia_storage_ffi: major
sia_storage: major
---

# Let a reconnecting user register a new app key

When `reconnecting()` is true, `register` / `connect_pre_authorized` no longer fail just because the recovery phrase derives a different app key; a new application key will be registered instead.

To let applications detect whether a recovery phrase matches an already-registered app key, this adds `matches_existing_app_key` (JS: `matchesExistingAppKey`).

This removes the `BuilderError::WrongRecoveryPhrase` variant.
