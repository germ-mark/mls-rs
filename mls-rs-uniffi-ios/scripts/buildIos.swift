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
}

try ScriptTask(
    path: FileManager().homeDirectoryForCurrentUser.appending(
        path: ".cargo/bin/cargo"
    ),
    arguments: ["build"]
)
.runExpectSuccess()
