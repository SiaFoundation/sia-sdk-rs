---
sia_storage_napi: patch
---

# Emit NAPI type definitions

Enable the `type-def` feature on `napi-derive` and add `ts_args_type` on `set_logger` so `napi build --dts` produces a usable `index.d.ts`.
