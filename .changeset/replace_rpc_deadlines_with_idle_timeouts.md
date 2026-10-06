---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
sia_storage_wasm: minor
---

# Replace fixed RPC deadlines with a per-RPC idle timeout

Sector reads and writes no longer run under a fixed 90 second deadline. Each RPC now fails once its stream has gone 6 seconds without making progress, so a stalled host is dropped quickly while a slow transfer that is still moving data is allowed to finish. `RPCError::Elapsed` is removed, along with the never-constructed `UploadError::Timeout` and `DownloadError::Timeout`; a stalled RPC surfaces as a timed-out I/O error.
