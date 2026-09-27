// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RoviaRouting",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RoviaRouting", targets: ["RoviaRouting"])
    ],
    dependencies: [
        .package(path: "../config")
    ],
    targets: [
        .target(
            name: "RoviaRouting",
            dependencies: [
                .product(name: "RoviaConfig", package: "config")
            ]
        ),
        .testTarget(
            name: "RoviaRoutingTests",
            dependencies: [
                "RoviaRouting",
                .product(name: "RoviaConfig", package: "config")
            ]
        )
    ]
)
