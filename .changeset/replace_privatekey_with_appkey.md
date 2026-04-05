---
sia_storage: minor
sia_storage_ffi: minor
---

# Replace PrivateKey with AppKey in public API

Replaced all uses of `PrivateKey` in the public API with `AppKey`. `PrivateKey` is no longer re-exported.

Added `UploadOptions::validate` to check erasure coding parameters for sufficient durability.

Made internal `app_client::Client` methods `pub(crate)` and moved data types (`App`, `Account`, `GeoLocation`, `HostQuery`, `ObjectsCursor`) to `lib.rs`.

Added doc strings to all public items.
