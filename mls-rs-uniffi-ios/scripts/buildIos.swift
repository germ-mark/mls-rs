#!/usr/bin/env swift
import Foundation

struct ScriptTask {
    let path: URL
    let arguments: [String]
    
    func run(allowingExitCodes codes: [Int32] = [0]) throws {
        let process = try Process.run(
            path,
            arguments: arguments
            
        )
        process.waitUntilExit()
        let terminationStatus = process.terminationStatus
        guard terminationStatus == 0 || codes.contains(terminationStatus) else {
            print("\(path) failed with exit code \(process.terminationStatus)")
            exit(-1)
        }
    }
}

let cargoPath = FileManager().homeDirectoryForCurrentUser.appending(
    path: ".cargo/bin/cargo"
)

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./ios/MLSrs.xcframework"]
)
.run(allowingExitCodes: [1])

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./ios/MLSrs.xcframework.zip"]
)
.run(allowingExitCodes: [1])


try ScriptTask(
    path: cargoPath,
    arguments: ["clean"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: [
        "run", "-p", "uniffi-bindgen",
        "--bin", "uniffi-bindgen",
        "generate", "--library", "../target/debug/libmls_rs_uniffi_ios.dylib",
        "--language", "swift",
        "--out-dir", "./bindings"
    ]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios-sim"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios"]
)
.run()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=x86_64-apple-darwin"]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/mv"),
    arguments: ["bindings/mls_rs_uniffi_iosFFI.modulemap", "bindings/module.modulemap"]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/xcodebuild"),
    arguments: [
        "-create-xcframework",
        "-library", "../target/aarch64-apple-ios-sim/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        "-library", "../target/aarch64-apple-ios/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        "-output", "ios/MLSrs.xcframework"
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/zip"),
    arguments: [
        "-r", "ios/MLSrs.xcframework.zip", "ios/MLSrs.xcframework"
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/swift"),
    arguments: [
        "package", "compute-checksum", "ios/MLSrs.xcframework.zip"
    ]
)
.run()
