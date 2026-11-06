---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
sia_storage_cabi: patch
---

# Keep browser uploads moving when some hosts do not answer

In the browser, uploads stalled for minutes when some hosts never answered a WebTransport handshake. Uploads tried new hosts before ones they had measured, and in Chrome each handshake that never completes delays the next. Uploads and downloads on every platform now rank a measured host above an untried one with the same failure rate.
