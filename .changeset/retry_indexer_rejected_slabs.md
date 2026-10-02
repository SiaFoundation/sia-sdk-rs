---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Reupload slabs rejected by the indexer as too old

Fresh slab pin requests now include each sector's upload time. If the indexer
rejects a slab as too old, the SDK reuploads its retained shards and retries
pinning with fresh timestamps, up to three upload attempts. This replaces the
age estimate based on host-reported block heights and requires indexd#1068.
