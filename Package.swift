// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Epiphyte",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    dependencies: [
        // Embedded Tor for iOS (same library used by Onion Browser)
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.52.0"),
    ],
    targets: [
        .executableTarget(
            name: "Epiphyte",
            dependencies: [],
            path: "Sources",
            resources: [.process("Resources")]
        ),
    ]
)
