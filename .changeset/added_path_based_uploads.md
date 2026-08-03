---
sia_storage: minor
sia_storage_ffi: minor
sia_storage_napi: minor
---

# Added path-based uploads behind the `fs` feature.

`Sdk::upload_path` and `PackedUpload::add_path` open a file and read it to EOF, so callers uploading from disk no longer stream every chunk across the language boundary. The feature is unavailable on wasm32; the FFI and Node bindings enable it and expose `uploadPath`/`addPath`.
