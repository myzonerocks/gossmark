// swift-tools-version: 6.0
import PackageDescription

// The Swift package is a thin binding over the C surface: the header and the library come from
// `zig build c`, and everything in Sources/Gossmark is buffer handling done once so a caller
// never frees anything and never sees a raw pointer.
let package = Package(
    name: "Gossmark",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Gossmark", targets: ["Gossmark"]),
    ],
    targets: [
        .systemLibrary(name: "CGossmark", path: "sdk/swift/Sources/CGossmark"),
        .target(name: "Gossmark", dependencies: ["CGossmark"], path: "sdk/swift/Sources/Gossmark"),
        .testTarget(name: "GossmarkTests", dependencies: ["Gossmark"], path: "sdk/swift/Tests/GossmarkTests"),
    ]
)
