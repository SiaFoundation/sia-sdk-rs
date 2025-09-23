---
sia_sdk_derive: patch
sia_sdk: patch
indexd_ffi: patch
indexd: patch
---

# Use PublicKey for account key type

#170 by @chris124567

This will be needed if https://github.com/SiaFoundation/core/pull/362 is merged because it will have an unexpected prefix which will cause serde to fail.
