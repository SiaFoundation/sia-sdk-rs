---
sia_core: minor
---

# Added `RPCWriteSector::send_header` and `SectorRootAccumulator`.

A sector can now be written to a host in pieces as it is produced: `send_header` sends the request, the caller writes the body itself, and `complete` takes the root the caller accumulated over it with `SectorRootAccumulator`, which hashes a sector chunk by chunk.
