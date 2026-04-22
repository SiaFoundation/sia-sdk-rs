# Running

From the repo root, run the following:

```sh
cargo build --release --package=sia_storage_ffi
cargo run --package=sia_storage_ffi --bin uniffi-bindgen generate --library target/release/libsia_storage_ffi.dylib --language python --out-dir sia_storage_ffi/examples/python
mv target/release/libsia_storage_ffi.dylib sia_storage_ffi/examples/python
(cd sia_storage_ffi/examples/python && python3 example.py)
```
