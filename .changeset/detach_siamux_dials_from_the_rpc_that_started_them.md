---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
---

# Keep a SiaMux dial running when the RPC that started it is cancelled, for as long as another RPC is waiting on it.
