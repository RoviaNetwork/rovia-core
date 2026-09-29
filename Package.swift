// swift-tools-version: 6.0
import PackageDescription

// Umbrella for cross-repository consumers (rovia-engine, rovia app): one URL,
// exact pins, no sibling-checkout assumptions. The focussed manifests under
// core/ and engines/ stay for day-to-day development and per-package CI.
let package = Package(
    name: "rovia-core",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "RoviaConfig", targets: ["RoviaConfig"]),
        .library(name: "RoviaSubscription", targets: ["RoviaSubscription"]),
        .library(name: "RoviaRouting", targets: ["RoviaRouting"]),
        .library(name: "RoviaEngineAPI", targets: ["RoviaEngineAPI"])
    ],
    targets: [
        .target(
            name: "RoviaConfig",
            path: "core/config/Sources/RoviaConfig"
        ),
        .target(
            name: "RoviaSubscription",
            dependencies: ["RoviaConfig"],
            path: "core/subscription/Sources/RoviaSubscription"
        ),
        .target(
            name: "RoviaRouting",
            dependencies: ["RoviaConfig"],
            path: "core/routing/Sources/RoviaRouting"
        ),
        .target(
            name: "RoviaEngineAPI",
            dependencies: ["RoviaConfig"],
            path: "engines/api/Sources/RoviaEngineAPI"
        )
    ]
)
