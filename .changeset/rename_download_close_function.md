---
sia_core_derive: patch
sia_storage_ffi: patch
sia_storage_wasm: patch
sia_core: patch
sia_storage_napi: patch
sia_storage: patch
sia_mux: patch
---

# Rename download close function

#341 by @chris124567

Otherwise we get conflicts with the uniffi Kotlin generator.
