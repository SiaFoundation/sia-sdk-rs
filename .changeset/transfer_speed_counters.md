---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
sia_storage_wasm: minor
---

# Added `Sdk::transfer_stats` for measuring transfer speed.

Read the counters on whatever cadence suits the caller and divide the deltas for upload or download speed over that window. Active time is the union of the in-flight sector RPCs, so concurrent shards count once, gaps between transfers are left out, and time the process spent frozen is discounted. Exposed through the ffi, napi, and wasm bindings as `transferStats`.
