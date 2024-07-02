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
    path: URL(fileURLWithPath: "/bin/rm"),
    arguments: ["-rv", "./ios/libmls_rs_uniffi_ios_sim_combined.a"]
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
    arguments: ["build", "--release", "--target=x86_64-apple-ios"]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/bin/mv"),
    arguments: ["bindings/mls_rs_uniffi_iosFFI.modulemap", "bindings/module.modulemap"]
)
.run()

//We do want to use lipo to build a combined binary for arm and x86 simulator
//as XCode Cloud runs on x86
//https://forums.developer.apple.com/forums/thread/711294?answerId=722588022#722588022
try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/lipo"),
    arguments: [
        "-create",
        "-output", "ios/libmls_rs_uniffi_ios_sim_combined.a",
        "../target/aarch64-apple-ios-sim/release/libmls_rs_uniffi_ios.a",
        "../target/x86_64-apple-ios/release/libmls_rs_uniffi_ios.a",
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/xcodebuild"),
    arguments: [
        "-create-xcframework",
        //the ios framework
        "-library", "../target/aarch64-apple-ios/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        //the simulator framework combining arm and x86_64 targets
        "-library", "../target/x86_64-apple-ios/release/libmls_rs_uniffi_ios.a", "-headers", "./bindings",
        "-output", "ios/MLSrs.xcframework"
    ]
)
.run()

guard FileManager.default.changeCurrentDirectoryPath("./ios") else {
    print("Couldn't change directory")
    exit(-1)
}

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/zip"),
    arguments: [
        "-r", "MLSrs.xcframework.zip", "MLSrs.xcframework"
    ]
)
.run()

try ScriptTask(
    path: URL(fileURLWithPath: "/usr/bin/swift"),
    arguments: [
        "package", "compute-checksum", "MLSrs.xcframework.zip"
    ]
)
.run()
