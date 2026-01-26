// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Example",
    platforms: [
        .iOS(.v13),
        .macOS(.v11)
    ],
    dependencies: [
        // Reference the generated SiaSDK package
        .package(path: "../SiaSDK"),
    ],
    targets: [
        .executableTarget(
            name: "Example",
            dependencies: [
                .product(name: "SiaSDK", package: "SiaSDK"),
            ],
            path: "Sources"
        )
    ]
)
