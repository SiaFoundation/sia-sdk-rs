# SiaSDK for Swift

Swift bindings for Sia decentralized storage, built with Rust and UniFFI.

## Installation

### Swift Package Manager

Add SiaSDK to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/SiaFoundation/sia-sdk-rs", from: "1.0.0")
]
```

Or in Xcode: **File → Add Packages** → Enter repository URL.

### CocoaPods

Add to your `Podfile`:

```ruby
pod 'SiaSDK', '~> 1.0'
```

Then run `pod install`.

## Requirements

- iOS 13.0+ / macOS 11.0+
- Swift 5.9+
- Xcode 15.0+

## Usage

```swift
import SiaSDK

// Set up logging
setLogger(logger: MyLogger(), level: "debug")

// Create a builder and connect
let builder = try Builder(indexerUrl: "https://app.sia.storage")

// Request connection approval
_ = try await builder.requestConnection(meta: AppMeta(
    id: appId,
    name: "My App",
    description: "App description",
    serviceUrl: "https://myapp.com",
    logoUrl: nil,
    callbackUrl: nil
))

// Wait for user approval
let approvedBuilder = try await builder.waitForApproval()

// Register with a recovery phrase
let mnemonic = generateRecoveryPhrase()
let sdk = try await approvedBuilder.register(mnemonic: mnemonic)

// Upload data
let upload = await sdk.uploadPacked(options: UploadOptions())
let reader = BytesReader(data: myData)
try await upload.add(reader: reader)
let objects = try await upload.finalize()

// Download data
let writer = BytesWriter()
try await sdk.download(w: writer, object: objects[0], options: DownloadOptions())
```

## Building from Source

To build the XCFramework locally:

```sh
# Install Rust targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

# Build the XCFramework
./indexd_ffi/scripts/build-swift.sh
```

This generates:
- `indexd_ffi/bindings/swift/SiaSDKFFI.xcframework` - The binary framework
- `indexd_ffi/bindings/swift/Sources/SiaSDK/SiaSDK.swift` - Generated Swift bindings

## License

MIT License - see [LICENSE](../../../LICENSE) for details.
