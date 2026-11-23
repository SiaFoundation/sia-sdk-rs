---
sia_core: patch
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
sia_storage_cabi: patch
---

# Grow byte strings as they are decoded

Decoding a length-prefixed byte string now allocates at most one sector at a time and grows as the data arrives.
