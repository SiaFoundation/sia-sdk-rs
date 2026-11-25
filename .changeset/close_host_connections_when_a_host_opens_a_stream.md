---
sia_mux: minor
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_cabi: patch
---

# Close host connections when a host opens a stream

Add `sia_mux::dial_refusing_streams`, which treats a stream opened by the other side as a protocol violation and closes the connection. The SDK dials hosts with it, since hosts never open streams to clients.
