---
sia_storage: minor
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Uploads start sending each slab before it is fully read.

Slabs are encoded, encrypted and hashed in 256 KiB steps per sector, each step on its own task, and every sector write begins as soon as its first step is ready, so the first bytes reach the hosts after 2.5 MiB of input instead of after the whole slab. Natively the steps of a slab encode concurrently, which also lifts upload throughput. Retries and racing attempts replay the finished steps and then follow the producer.
