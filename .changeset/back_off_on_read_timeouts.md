---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Back off the download inflight limit when sector reads time out, instead of waiting for a goodput window that reads flat on a saturated link.
