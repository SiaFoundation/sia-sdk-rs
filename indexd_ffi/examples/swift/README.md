# Running

From the repo root, run the following:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
./indexd_ffi/examples/swift/build-xcframework.sh
(cd indexd_ffi/examples/swift/Example && swift run)
```
