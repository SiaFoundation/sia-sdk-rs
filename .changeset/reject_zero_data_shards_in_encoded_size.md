---
sia_storage_ffi: major
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Return an error from `encoded_size` when data shards is zero

Zero data shards divided by zero in the core SDK. In Node that aborted the process, and in WASM it threw an opaque `unreachable` error. The bindings now return a "data shards cannot be zero" error instead. The UniFFI `encoded_size` now throws, so Swift callers need `try`.
