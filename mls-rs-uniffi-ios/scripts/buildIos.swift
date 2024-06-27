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
