#!/usr/bin/env swift
import Foundation

struct ScriptTask {
    let path: URL
    let arguments: [String]
    
    func runExpectSuccess() throws {
        let process = try Process.run(
            path,
            arguments: arguments
            
        )
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            print("\(path) failed with exit code \(process.terminationStatus)")
            exit(-1)
        }
    }
    
    func runAllowingExitCodes(_ codes: [Int32]) throws {
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
    arguments: ["./ios/MLSrs.xcframework"]
)
.runAllowingExitCodes([1])


try ScriptTask(
    path: cargoPath,
    arguments: ["clean"]
)
.runExpectSuccess()

try ScriptTask(
    path: cargoPath,
    arguments: ["build"]
)
.runExpectSuccess()

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
.runExpectSuccess()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios-sim"]
)
.runExpectSuccess()

try ScriptTask(
    path: cargoPath,
    arguments: ["build", "--release", "--target=aarch64-apple-ios"]
)
.runExpectSuccess()

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/mv"),
    arguments: ["bindings/mls_rs_uniffi_iosFFI.modulemap", "bindings/module.modulemap"]
)
.runExpectSuccess()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/xcodebuild"),
    arguments: [
        "-create-xcframework",
        "-library", "../target/aarch64-apple-ios-sim/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        "-library", "../target/aarch64-apple-ios/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        "-output", "ios/MLSrs.xcframework"
    ]
)
.runExpectSuccess()
