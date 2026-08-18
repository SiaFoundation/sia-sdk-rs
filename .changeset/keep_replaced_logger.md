---
sia_storage_ffi: patch
---

# Fixed a crash when a logger is set again from a rebuilt foreign runtime.

Setting a logger replaces the stored handle, and releasing the old one calls back into the runtime that created it. A host that tears its runtime down and sets a logger again from the new one, as a React Native dev server reload does, left that release reading freed memory and taking the process down. The previous handle is now kept instead.
