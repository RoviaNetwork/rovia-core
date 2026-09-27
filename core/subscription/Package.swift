// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RoviaSubscription",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RoviaSubscription", targets: ["RoviaSubscription"])
    ],
    dependencies: [
        .package(path: "../config")
    ],
    targets: [
        .target(
            name: "RoviaSubscription",
            dependencies: [
                .product(name: "RoviaConfig", package: "config")
            ]
        ),
        .testTarget(
            name: "RoviaSubscriptionTests",
            dependencies: [
                "RoviaSubscription",
                .product(name: "RoviaConfig", package: "config")
            ]
        )
    ]
)
