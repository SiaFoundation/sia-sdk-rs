---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_wasm: minor
sia_storage_napi: minor
---

# Added `connect_pre_authorized` for connecting with a pre-authorized key.

Applications can now bypass the interactive approval flow by connecting with a pre-authorized key that the indexer operator provisions out of band. `Builder::connect_pre_authorized(pre_authorized_key, mnemonic)` performs the connect, approval, and registration steps in one call and returns a ready SDK. The method is also exposed through the ffi, napi, and wasm bindings.
