# Running

From the repo root, run the following:

```sh
cargo build --release --package=indexd_ffi
cargo run --package=indexd_ffi --bin uniffi-bindgen generate --library target/release/libindexd_ffi.dylib --language python --out-dir indexd_ffi/examples/python
mv target/release/libindexd_ffi.dylib indexd_ffi/examples/python
(cd indexd_ffi/examples/python && python3 example.py)
```
