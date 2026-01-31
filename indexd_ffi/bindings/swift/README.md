# SiaSDK for Swift

Swift bindings for Sia decentralized storage, built with Rust and UniFFI.

## Requirements

- iOS 13.0+ / macOS 11.0+
- Swift 5.9+
- Xcode 15.0+

## Usage

### Swift Package Manager

```swift
.package(url: "https://github.com/SiaFoundation/sia-sdk-rs", from: "0.3.0")
```

### CocoaPods

```ruby
pod 'SiaSDK', '~> 0.3'
```

### Local Development

```sh
# Install Rust targets (first time only)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

# Build and run example
./indexd_ffi/scripts/build-swift.sh
cd indexd_ffi/examples/swift/Example
SIA_SDK_USE_LOCAL_XCFRAMEWORK=1 swift run
```

## Example

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

## License

MIT License - see [LICENSE](../../../LICENSE) for details.
