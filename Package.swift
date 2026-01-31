// swift-tools-version: 5.9
import Foundation
import PackageDescription

// Set SIA_SDK_USE_LOCAL_XCFRAMEWORK=1 to use a locally-built XCFramework.
let useLocalBinary = ProcessInfo.processInfo.environment["SIA_SDK_USE_LOCAL_XCFRAMEWORK"] == "1"

let binaryTarget: Target = useLocalBinary
    ? .binaryTarget(
        name: "SiaSDKFFI",
        path: "indexd_ffi/bindings/swift/build/SiaSDKFFI.xcframework"
    )
    : .binaryTarget(
        name: "SiaSDKFFI",
        url: "https://github.com/SiaFoundation/sia-sdk-rs/releases/download/v0.3.0/SiaSDKFFI-0.3.0.xcframework.zip",
        checksum: "ff957339090a58e734de895df0df4b767377772e7b0bec482ee97bae940eebc4"
    )

let package = Package(
    name: "SiaSDK",
    platforms: [
        .iOS(.v13),
        .macOS(.v11)
    ],
    products: [
        .library(name: "SiaSDK", targets: ["SiaSDK"])
    ],
    targets: [
        binaryTarget,
        .target(
            name: "SiaSDK",
            dependencies: ["SiaSDKFFI"],
            path: "Sources/SiaSDK",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration")
            ]
        )
    ]
)
