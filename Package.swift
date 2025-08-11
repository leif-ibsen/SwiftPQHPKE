// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftPQHPKE",
    platforms: [.macOS(.v10_15), .iOS(.v13), .watchOS(.v8)], // Due to the use of the CryptoKit framework
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftPQHPKE",
            targets: ["SwiftPQHPKE"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.13.0"),
        .package(url: "https://github.com/leif-ibsen/SwiftKyber", from: "3.4.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftPQHPKE",
            dependencies: ["ASN1", "BigInt", "Digest", "SwiftKyber"]),
        .testTarget(
            name: "SwiftPQHPKETests",
            dependencies: ["SwiftPQHPKE"]
        ),
    ]
)
