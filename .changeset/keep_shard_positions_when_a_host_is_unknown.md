---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Fix a crash reading a slab with a host the SDK does not know

A slab whose sectors include a host missing from the SDK's host list, such as one an indexer stopped listing, crashed the download with "index out of bounds: the len is 29 but the index is 29". Sectors on unknown hosts are dropped before reading, and the array the recovered shards are stored in was sized from the sectors left rather than from the slab's shard count, while each shard is stored at its index in the slab. A read from the host at the slab's last index then wrote past the end. In a browser the panic stops the WebAssembly module, so every stream in the page froze with no error. The array is now sized from the slab's shard count.
