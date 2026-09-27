// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RoviaEngineAPI",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RoviaEngineAPI", targets: ["RoviaEngineAPI"])
    ],
    dependencies: [
        .package(path: "../../core/config")
    ],
    targets: [
        .target(
            name: "RoviaEngineAPI",
            dependencies: [
                .product(name: "RoviaConfig", package: "config")
            ]
        ),
        .testTarget(
            name: "RoviaEngineAPITests",
            dependencies: [
                "RoviaEngineAPI",
                .product(name: "RoviaConfig", package: "config")
            ]
        )
    ]
)
