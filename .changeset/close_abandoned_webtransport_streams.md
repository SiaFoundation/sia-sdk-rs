---
sia_storage: patch
sia_storage_wasm: patch
---

# Close WebTransport streams whose open was abandoned

When opening a bidirectional stream timed out or the read waiting on it was cancelled, a stream the browser opened afterwards was never used or closed. These streams piled up on the host's session until it stopped accepting new ones, and reads from that host stalled. A stream that opens after its caller gave up is now closed right away.
