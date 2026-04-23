---
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Simplify `PackedUpload` binding internals

Replaced the per-upload mpsc actor with a mutex and a cancellation token. Errors from `add` and `finalize` now propagate directly instead of through a oneshot that could swallow them, and no background task is kept per upload. No public API change.
