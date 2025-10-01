---
sia_sdk: minor
indexd_ffi: minor
sia_sdk_derive: minor
indexd: minor
---

# Add method for pinning multiple slabs

#180 by @chris124567

After https://github.com/SiaFoundation/indexd/pull/427 is merged, we will need to send an array of SlabPinParams to the pin slabs endpoint.  This PR makes the changes needed for that and also adds in helpers that preserve the old `pin_slab` functionality.

