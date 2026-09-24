---
sia_storage_ffi: minor
---

# Added `TransferProgress` for polling transfer progress.

Construct a `TransferProgress`, pass it as the `progress` option to an upload, packed upload, or download, and read `shards()` and `shard_bytes()` on whatever cadence suits the caller. Each read is a single atomic load, so progress no longer costs a call into the foreign language per shard. `ProgressCallback` is unchanged and the two can be set together.
