#!/usr/bin/env bash
set -euo pipefail

# Build XCFramework and Swift package for SiaSDK
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
#                     aarch64-apple-darwin x86_64-apple-darwin

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CRATE="indexd_ffi"
LIB="libindexd_ffi"
FFI_MODULE="SiaSDKFFI"
SWIFT_MODULE="SiaSDK"

SWIFT_DIR="$REPO_ROOT/indexd_ffi/bindings/swift"
BUILD_DIR="$SWIFT_DIR/build"
GEN_DIR="$SWIFT_DIR/generated"
PACKAGE_DIR="$REPO_ROOT"

cd "$REPO_ROOT"

# Build all Apple targets
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build -p "$CRATE" --release --target "$target"
done

# Build host dylib for uniffi-bindgen
cargo build -p "$CRATE" --release

# Generate Swift bindings
mkdir -p "$GEN_DIR"
cargo run -p "$CRATE" --bin uniffi-bindgen -- \
    generate --library "target/release/${LIB}.dylib" \
    --language swift \
    --out-dir "$GEN_DIR" \
    --config "$REPO_ROOT/indexd_ffi/uniffi.toml"

# Create fat binaries
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{ios-device,ios-simulator,macos}/Headers

cp "target/aarch64-apple-ios/release/${LIB}.a" "$BUILD_DIR/ios-device/"

lipo -create \
    "target/aarch64-apple-ios-sim/release/${LIB}.a" \
    "target/x86_64-apple-ios/release/${LIB}.a" \
    -output "$BUILD_DIR/ios-simulator/${LIB}.a"

lipo -create \
    "target/aarch64-apple-darwin/release/${LIB}.a" \
    "target/x86_64-apple-darwin/release/${LIB}.a" \
    -output "$BUILD_DIR/macos/${LIB}.a"

# Stage headers
for platform in ios-device ios-simulator macos; do
    cp "$GEN_DIR/${FFI_MODULE}.h" "$BUILD_DIR/$platform/Headers/"
    cp "$GEN_DIR/${FFI_MODULE}.modulemap" "$BUILD_DIR/$platform/Headers/module.modulemap"
done

# Create XCFramework
xcodebuild -create-xcframework \
    -library "$BUILD_DIR/ios-device/${LIB}.a" \
    -headers "$BUILD_DIR/ios-device/Headers" \
    -library "$BUILD_DIR/ios-simulator/${LIB}.a" \
    -headers "$BUILD_DIR/ios-simulator/Headers" \
    -library "$BUILD_DIR/macos/${LIB}.a" \
    -headers "$BUILD_DIR/macos/Headers" \
    -output "$BUILD_DIR/${FFI_MODULE}.xcframework"

# Assemble Swift package sources at repo root
mkdir -p "$PACKAGE_DIR/Sources/$SWIFT_MODULE"
cp "$GEN_DIR/${SWIFT_MODULE}.swift" "$PACKAGE_DIR/Sources/$SWIFT_MODULE/"

echo "Swift package sources updated at: $PACKAGE_DIR/Sources/$SWIFT_MODULE"

# Distribution zip with checksum
(cd "$BUILD_DIR" && zip -rq "${FFI_MODULE}.xcframework.zip" "${FFI_MODULE}.xcframework")
CHECKSUM=$(swift package compute-checksum "$BUILD_DIR/${FFI_MODULE}.xcframework.zip")

echo ""
echo "=== Build Complete ==="
echo "XCFramework: $BUILD_DIR/${FFI_MODULE}.xcframework"
echo "Distribution zip: $BUILD_DIR/${FFI_MODULE}.xcframework.zip"
echo "Checksum: $CHECKSUM"
echo ""
echo "To use locally, set SIA_SDK_USE_LOCAL_XCFRAMEWORK=1 and add this to your Package.swift dependencies:"
echo "  .package(path: \"path/to/sia-sdk-rs\")"
