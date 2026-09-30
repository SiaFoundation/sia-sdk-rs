---
sia_storage: patch
---

# Record a host failure when a sector read times out

`read_sector` recorded a failure only when the RPC itself returned an error. A
timeout dropped that future without the hook running, so a host that stopped
answering reads kept no samples and a 0% failure rate, which host selection
ranks above every measured host as a discovery preference. The host that just
timed out was picked first again. `write_sector` already had this arm.
