// swift-tools-version:6.0
import Foundation
import PackageDescription

// The manifest a consumer resolves. The core arrives as the XCFramework a checkout built with
// tools/build-xcframework.sh, so a consumer needs no Zig and no build step of its own. When that
// framework is not there the manifest still resolves, against the one attached to a release, so
// a fresh clone is not a broken clone.
let localKit = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent("zig-out/GossmarkKit.xcframework").path
let kit: Target = FileManager.default.fileExists(atPath: localKit)
    ? .binaryTarget(name: "GossmarkKit", path: "zig-out/GossmarkKit.xcframework")
    : .binaryTarget(
        name: "GossmarkKit",
        url: "https://github.com/myzonerocks/gossmark/releases/download/v0.1.0-alpha.1/GossmarkKit.xcframework.zip",
        checksum: "7096f13f6594f2fd0723ad5a1d0e5b4b6d81d701bc7eb2c72a8328f96122ec70"
    )

let package = Package(
    name: "Gossmark",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Gossmark", targets: ["Gossmark"]),
        .library(name: "GossmarkKit", targets: ["GossmarkKit"]),
    ],
    targets: [
        kit,
        .target(name: "Gossmark", dependencies: ["GossmarkKit"], path: "sdk/swift/Sources/Gossmark"),
        .testTarget(name: "GossmarkTests", dependencies: ["Gossmark"], path: "sdk/swift/Tests/GossmarkTests"),
    ]
)
