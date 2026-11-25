---
sia_core: major
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
sia_storage_cabi: patch
---

# Bound sector read responses

`bytes::Bytes` no longer implements `SiaDecodable` or `AsyncSiaDecodable`, and `RangeProof` no longer implements `SiaDecodable`. Range proofs are decoded with limits on their proof and data lengths, and a sector read stops reading once the response is larger than the requested range allows.
