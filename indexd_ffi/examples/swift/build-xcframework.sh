#!/usr/bin/env bash
set -euo pipefail

# Build XCFramework and Swift package for SiaSDK
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
#                     aarch64-apple-darwin x86_64-apple-darwin

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

CRATE="indexd_ffi"
LIB="libindexd_ffi"
FFI_MODULE="SiaSDKFFI"
SWIFT_MODULE="SiaSDK"

BUILD_DIR="$SCRIPT_DIR/build"
GEN_DIR="$SCRIPT_DIR/generated"
SDK_DIR="$SCRIPT_DIR/SiaSDK"

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
    --out-dir "$GEN_DIR"

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

# Assemble Swift package
rm -rf "$SDK_DIR"
mkdir -p "$SDK_DIR/Sources/$SWIFT_MODULE"

cp -r "$BUILD_DIR/${FFI_MODULE}.xcframework" "$SDK_DIR/"
cp "$GEN_DIR/${SWIFT_MODULE}.swift" "$SDK_DIR/Sources/$SWIFT_MODULE/"

cat > "$SDK_DIR/Package.swift" << 'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SiaSDK",
    platforms: [.iOS(.v13), .macOS(.v11)],
    products: [
        .library(name: "SiaSDK", targets: ["SiaSDK"])
    ],
    targets: [
        .binaryTarget(name: "SiaSDKFFI", path: "SiaSDKFFI.xcframework"),
        .target(name: "SiaSDK", dependencies: ["SiaSDKFFI"])
    ]
)
EOF

# Distribution zip with checksum
(cd "$BUILD_DIR" && zip -rq "${FFI_MODULE}.xcframework.zip" "${FFI_MODULE}.xcframework")
swift package compute-checksum "$BUILD_DIR/${FFI_MODULE}.xcframework.zip"
