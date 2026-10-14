---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
sia_storage_wasm: minor
---

# List object events without slabs

Add `Sdk::object_event_summaries` (`objectEventSummaries` in JavaScript), which lists the same object events as `Sdk::object_events` without the objects' slabs, making the response much smaller. Each event has an `ObjectSummary` with the object's id, size, decrypted metadata and timestamps, and paginates with the same cursor. Fetch the full object with `Sdk::object` to download it.
