---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Take a read's account token once the stream to the host is open

A sector read took its account token before reaching the host. When reaching the host took a long time, as in a browser delaying WebTransport connections after failed handshakes, the token expired on the way and the host rejected the read with "account token expired". The transports now take the token from the token source after the stream to the host is open.
