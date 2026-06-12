---
sia_storage_ffi: patch
sia_storage_wasm: patch
sia_storage_napi: patch
sia_storage: patch
---

# Made racing adaptive so that racers will not steal slots from higher priority work

For uploads, racing will only start when every shard has an attempt in flight. For downloads, racing will only start when the chunk is near the read head. The race timeout is derived from the p95 of recently completed RPCs instead of a fixed interval so only hosts well outside the normal latency spread get raced.
