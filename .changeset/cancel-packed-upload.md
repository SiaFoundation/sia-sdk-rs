---
sia_storage: minor
sia_storage_wasm: minor
sia_storage_napi: minor
---

Packed uploads can be cancelled, shard write attempts are reported, and the approval poll is the caller's.

- `PackedUpload::finalize` borrows instead of consuming, so `cancel()` still works while the upload runs. The wasm binding used to destroy the handle when `finalize` started, which left JavaScript with nothing to cancel.
- `onShardAttempted` reports every shard write attempt, failures included, with the host, the shard and slab index, the elapsed time, and the reason. `shard_uploaded` only reports successes, so a caller could not name the host holding a slab up.
- `wait_for_approval_with(interval, on_check)` takes the poll interval and a callback that runs after every check and decides whether to keep waiting. Previously the five second interval was fixed inside the SDK, with no callback and no way to stop.
