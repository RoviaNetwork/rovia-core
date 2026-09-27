// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RoviaConfig",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RoviaConfig", targets: ["RoviaConfig"])
    ],
    targets: [
        .target(name: "RoviaConfig"),
        .testTarget(name: "RoviaConfigTests", dependencies: ["RoviaConfig"])
    ]
)
