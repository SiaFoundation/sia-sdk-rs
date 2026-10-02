---
sia_mux: patch
---

# Detect idle streams in SiaMux

Add an optional stream idle timeout that tracks incoming payloads and partial writes to the underlying connection.
