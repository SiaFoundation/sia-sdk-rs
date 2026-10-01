---
sia_storage_wasm: patch
---

# Fix the generated type declarations for `Sdk` and `SharedSdk`

Both were declared as a bare `interface` in a `typescript_custom_section`
alongside the exported class of the same name. TypeScript refuses to merge
declarations that are not all exported or all local, so the interface shadowed
the class and anything returning an `Sdk` appeared to hand back a type with
three members. Exporting the interfaces lets them merge, which is what they were
always meant to do.
