---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Fix connecting to hosts that announce an IPv6 address

An announced address is `host:port` with an IPv6 host bracketed. The siamux client split it on the last colon, which left the brackets attached to the host, and `getaddrinfo` rejects those, so every IPv6 host failed to resolve and no shard could reach it. The address is now resolved whole.
