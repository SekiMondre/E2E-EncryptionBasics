// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "E2EEncryptionBasics",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "E2EEncryptionBasics"),
    ]
)
