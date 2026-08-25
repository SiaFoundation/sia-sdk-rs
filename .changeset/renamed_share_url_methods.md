---
sia_storage: major
sia_storage_ffi: major
sia_storage_napi: major
sia_storage_wasm: major
---

# Renamed the share URL methods on `Sdk`.

`Sdk::share_object` and `Sdk::shared_object` are now `Sdk::object_share_url` and `Sdk::object_from_share_url`. The bindings change to match, so `shareObject` and `sharedObject` become `objectShareUrl` and `objectFromShareUrl`.
