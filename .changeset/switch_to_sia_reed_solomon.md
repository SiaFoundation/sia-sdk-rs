---
sia_storage: minor
---

# Switch to sia_reed_solomon for erasure-coding

Replaced `reed-solomon-erasure` with `sia_reed_solomon`. Encoded parity bytes
are compatible with existing `indexd` slabs.

120 MiB upload against the mock cluster
(`cargo bench -p sia_storage --features mock`):

| | Before | After | Δ |
|---|---|---|---|
| `upload/90 inflight` | ~285 MiB/s | **469 MiB/s** | **+67%** |
| `upload/10 inflight` | ~175 MiB/s | **457 MiB/s** | **+161%** |
| `upload/default`     | ~184 MiB/s | **471 MiB/s** | **+155%** |
