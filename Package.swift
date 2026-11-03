// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Tether",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Tether", targets: ["Tether"]),
    ],
    targets: [
        .target(name: "Tether"),
        .testTarget(name: "TetherTests", dependencies: ["Tether"]),
    ]
)
