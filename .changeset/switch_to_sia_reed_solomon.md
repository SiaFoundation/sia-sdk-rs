---
sia_storage: major
---

# Switch to sia_reed_solomon for erasure-coding

Replaced `reed-solomon-erasure` with `sia_reed_solomon`. Encoded parity bytes
are compatible with existing `indexd` slabs.

120 MiB upload against the mock cluster
(`cargo bench -p sia_storage --all-features`):

| | Before | After | Δ |
|---|---|---|---|
| `upload/90 inflight` | ~285 MiB/s | **611 MiB/s** | **+114%** |
| `upload/10 inflight` | ~175 MiB/s | **595 MiB/s** | **+240%** |
| `upload/default`     | ~184 MiB/s | **609 MiB/s** | **+231%** |
