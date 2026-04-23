---
sia_storage: major
sia_storage_ffi: major
sia_storage_napi: major
sia_storage_wasm: major
---

# Rename `slab_size` to `optimal_data_size` where it refers to the data-only portion

Methods and fields that previously returned or stored `data_shards * SECTOR_SIZE` (the packing period for `PackedUpload`) are now named `optimal_data_size` to distinguish them from the true encoded slab size (`total_shards * SECTOR_SIZE`, which remains `slab_size`). Affects `PackedUpload::slab_size()` (Rust, FFI, NAPI) and the `slabSize` JS getter (now `optimalDataSize`).

`UploadOptions::slab_size()`, `UploadOptions::optimal_data_size()`, `PackedUpload::optimal_data_size()`, and `PackedUpload::slabs()` now return `usize` instead of `u64`.

Also fixes a NAPI bug where `upload_packed` was storing the total slab size (including parity) into the field used as the slab size, causing `remaining` / `slabs` to report incorrect values.
