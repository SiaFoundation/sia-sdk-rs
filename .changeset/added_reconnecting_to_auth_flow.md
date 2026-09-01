---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_wasm: minor
sia_storage_napi: minor
---

# Added `reconnecting` to the connection approval flow.

After approval, `reconnecting()` reports whether the connect key already has an account for the application. When reconnecting, `register` and `connect_pre_authorized` fail with `WrongRecoveryPhrase` if the recovery phrase does not match the existing account.
