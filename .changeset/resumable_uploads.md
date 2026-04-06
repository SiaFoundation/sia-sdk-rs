---
sia_storage: major
sia_storage_ffi: major
---

# Resumable uploads

`SDK::upload` now takes an `Object` parameter and appends uploaded slabs to it. This enables resumable uploads by passing the same object back to `upload` with a new reader.

For new uploads, pass `Object::default()` (Rust) or `PinnedObject::new()` (FFI). This is a breaking change to the upload API signature.
