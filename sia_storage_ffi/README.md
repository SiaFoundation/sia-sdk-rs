# sia_storage_ffi

Foreign function interface bindings for `sia_storage`, generated with [UniFFI](https://mozilla.github.io/uniffi-rs/).

This crate exposes the Sia storage SDK to non-Rust languages including Swift, Kotlin, and Python. It wraps `sia_storage` with a UniFFI-compatible API that handles async runtime management and type conversions.

## Supported platforms

- iOS / macOS (Swift)
- Android (Kotlin)
- Python

## Building

The crate produces a C-compatible dynamic library (`cdylib`) and a static library (`staticlib`). To generate language bindings:

```bash
# Build the library
cargo build -p sia_storage_ffi --release

# Generate Swift bindings
cargo run -p sia_storage_ffi --bin uniffi-bindgen generate \
    --library target/release/libsia_storage_ffi.dylib \
    --language swift \
    --out-dir out/swift

# Generate Kotlin bindings
cargo run -p sia_storage_ffi --bin uniffi-bindgen generate \
    --library target/release/libsia_storage_ffi.so \
    --language kotlin \
    --out-dir out/kotlin
```

## API overview

The FFI API mirrors `sia_storage` with adaptations for cross-language compatibility:

- **`Builder`** -- Connect to an indexer and complete the approval flow.
- **`SDK`** -- Upload, download, and manage objects.
- **`AppKey`** -- Import, export, and use application keys.
- **`Object` / `SealedObject`** -- Represent stored data and its encrypted form.

Async methods are automatically dispatched on a Tokio runtime managed by the library.

## License

This project is licensed under the MIT License.
