---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
sia_storage_wasm: minor
---

# Added `Builder::init` to share one host connection pool across every `Sdk` and `SharedSdk` created with `for_app` and `for_sharing_key`, exposed in the bindings as `SharedBuilder`.
