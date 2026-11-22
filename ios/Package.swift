// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "GhostTag",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "GhostTagCore",
            targets: ["GhostTagCore"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Clibargon2",
            path: "GhostTag/Vendors/Clibargon2",
            publicHeadersPath: "include",
            cSettings: [
                .define("ARGON2_NO_THREADS", to: "1")
            ]
        ),
        .target(
            name: "GhostTagCore",
            dependencies: ["Clibargon2"],
            path: "GhostTag/Core"
        ),
        .testTarget(
            name: "GhostTagTests",
            dependencies: ["GhostTagCore"],
            path: "GhostTagTests",
            resources: [
                .copy("Fixtures")
            ]
        ),
    ]
)
