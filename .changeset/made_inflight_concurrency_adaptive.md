---
sia_storage: major
sia_storage_ffi: major
sia_storage_wasm: major
sia_storage_napi: major
---

# Added adaptive transfer concurrency

Uploads and downloads no longer take a fixed `max_inflight` concurrency limit — concurrency now adapts to network conditions automatically. Memory use is bounded directly instead, by two new options: `UploadOptions::max_buffered_slabs` and `DownloadOptions::max_buffered_chunks`, each defaulting to roughly 10% of system memory when unset. The `max_inflight` field is removed from the upload, download, and language-binding option types.
