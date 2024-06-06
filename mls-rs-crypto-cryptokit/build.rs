// This script should not run on any platform besides macOS, but making the whole file conditional
// results in `cargo` complaining about there being no `main()` method in build.rs.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {}

#[cfg(any(target_os = "macos", target_os = "ios"))]
use swift_rs::SwiftLinker;

fn main() {
    SwiftLinker::new("14.0")
    // Only if you are also targetting iOS
    // Ensure the same minimum supported iOS version is specified as in your `Package.swift` file
         .with_ios("17.0")
         .with_package("cryptokit-bridge", "./cryptokit-bridge")
         .link();
}
