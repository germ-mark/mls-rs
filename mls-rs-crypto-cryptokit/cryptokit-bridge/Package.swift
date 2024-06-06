// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "cryptokit-bridge",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "cryptokit-bridge",
                 type: .static,
                 targets: ["cryptokit-bridge"]),
    ],
    dependencies: [.package(url: "https://github.com/Brendonovich/swift-rs", from: "1.0.5")],
    targets: [
        .target(name: "cryptokit-bridge",
                dependencies: [.product(
                    name: "SwiftRs",
                    package: "swift-rs"
                )]),
        .testTarget(name: "cryptokit-bridge-tests",
                    dependencies: ["cryptokit-bridge",
                                   .product(
                                    name: "SwiftRs",
                                    package: "swift-rs"
                                   )])
    ]
)
