---
sia_storage_ffi: minor
sia_storage: minor
sia_storage_wasm: minor
sia_storage_napi: minor
---

# Added `start_offset` to `UploadOptions`.

This allows objects to be rewritten without reuploading the entire object. The original object is not replaced, so both versions can be pinned simultaneously.