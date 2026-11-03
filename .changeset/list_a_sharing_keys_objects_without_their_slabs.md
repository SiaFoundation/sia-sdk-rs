---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
sia_storage_wasm: minor
sia_storage_cabi: minor
---

# Add `Sdk::shared_object_summaries`, which lists the objects attached to one of the account's sharing keys without their slabs

It returns the same `ObjectSummary` as `SharedSdk::object_summaries`, with each object's id, size, decrypted metadata and timestamps, so an owner can show what a key shares without fetching every object's slabs. The WASM and NAPI bindings expose it as `sharedObjectSummaries`, the FFI binding as `shared_object_summaries`, and the C ABI as `sia_sdk_shared_object_summaries`, which is read with the existing `sia_object_summaries_*` functions.
