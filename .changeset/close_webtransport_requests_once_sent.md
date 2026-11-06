---
sia_storage: patch
sia_storage_wasm: patch
---

# Fix Firefox uploads and downloads failing against hosts on coreutils 0.25.1 and later

In Firefox, uploads could run out of hosts and downloads could fail with too few shards, because sector writes and reads failed with "Error in input stream". Hosts on coreutils 0.25.1 and later stop reading a stream when an RPC ends, and Firefox discarded the rest of the host's response when the SDK's side of the stream was still open. The SDK now closes its side as soon as the request is written.
