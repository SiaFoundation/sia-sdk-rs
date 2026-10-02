---
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Report a whole slab free once one fills

A slab that filled exactly reported 0 bytes free instead of a whole empty slab. A caller using it 
to decide what to add next was told every further object would start a new slab.
