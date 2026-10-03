---
sia_storage: major
sia_storage_ffi: major
sia_storage_napi: major
sia_storage_wasm: major
---

# Remove `Sdk::slab`

A slab id is `Slab::digest()`, derived from the sector roots rather than stored,
and no binding exposed a way to obtain one. `sdk.slab(id)` therefore took an
argument its callers could not produce. The lookup is gone from the native SDK
and from the uniffi, napi and wasm bindings, along with the `PinnedSlab` each of
them mirrored for it. `sia_storage::PinnedSlab` goes too, since nothing public
returned it once the lookup was gone.
