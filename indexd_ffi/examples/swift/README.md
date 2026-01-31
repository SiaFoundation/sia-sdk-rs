# Swift Example

This is an example application demonstrating the SiaSDK Swift package.

## Prerequisites

First, build the Swift package from the repo root:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
./indexd_ffi/scripts/build-swift.sh
```

## Running the Example

```sh
cd indexd_ffi/examples/swift/Example
SIA_SDK_USE_LOCAL_XCFRAMEWORK=1 swift run
```
