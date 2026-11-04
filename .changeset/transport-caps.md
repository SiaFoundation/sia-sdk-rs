---
sia_storage: minor
sia_storage_wasm: minor
---

The WebTransport connect and transfer phases are bounded, and the caller can set the bounds.

- A session that does not open in 15 seconds is dropped. It used to be 60. A host that took
  longer than 15 seconds to connect also took 20 to 50 seconds to write a shard, so the cap
  also filters hosts that would be slow to write.
- Each RPC now has a 30 second total budget from stream open. The idle clock only bounded
  gaps between progress, so a host that trickled a 64 KiB chunk every few seconds could hold
  its upload slot indefinitely.
- `Builder::set_timeouts` and `setTimeouts(connect_ms, transfer_ms)` override both before
  connecting. The defaults are 15 and 30 seconds. The transport is shared, so the limits
  apply to every SDK created afterwards on the runtime.
