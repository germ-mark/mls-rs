#!/usr/bin/env swift
import Foundation

let homeDirectoryURL = FileManager().homeDirectoryForCurrentUser

let cargoBuild = try Process.run(
    homeDirectoryURL.appending(path: ".cargo/bin/cargo"),
    arguments: ["build"]
)
cargoBuild.waitUntilExit()

guard cargoBuild.terminationStatus == 0 else {
    print("cargo build failed with exit code \(cargoBuild.terminationStatus)")
    exit(-1)
}
