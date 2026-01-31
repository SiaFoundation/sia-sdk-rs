// swift-tools-version: 5.9
import PackageDescription

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
        .binaryTarget(
            name: "SiaSDKFFI",
            path: "SiaSDKFFI.xcframework"
        ),
        .target(
            name: "SiaSDK",
            dependencies: ["SiaSDKFFI"],
            path: "Sources/SiaSDK"
        )
    ]
)
