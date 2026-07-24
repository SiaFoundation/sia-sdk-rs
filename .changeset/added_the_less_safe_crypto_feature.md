---
sia_storage: minor
---

# Added the `less-safe-crypto` feature.

The feature exposes `Object::less_safe_new` and `Object::data_key` for exporting an object's data key and reconstructing the object from externally persisted components. The caller is responsible for the invariants the upload path normally enforces.
