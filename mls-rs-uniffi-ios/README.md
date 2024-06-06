# iOS XCFramework
Build toolchain to generate a XCFramework for mls-rs for an iOS app, using uniffi to generate bindings

# Steps:
(preamble - run once)
Add ios targets to Rust:
```
rustup target add aarch64-apple-ios-sim aarch64-apple-ios
```

(following steps are run from this crate's directory, within the mls-rs workspace)
1. Build the library
```
cargo build
```

2. Generate the bindings 
```
cargo run -p uniffi-bindgen --bin uniffi-bindgen \
	generate --library ../target/debug/libmls_rs_uniffi_ios.dylib --language swift \
	--out-dir ./bindings
```

3. Build for Swift:
```
cargo build --release --target=aarch64-apple-ios-sim && \ 
cargo build --release --target=aarch64-apple-ios
```

4. Create XCFramework
first rename `bindings/[project name]FFI.modulemap` to `bindings/module.modulemap`:
```
mv bindings/mls_rs_uniffi_iosFFI.modulemap bindings/module.modulemap
```


Then package the xcframework:
```
 xcodebuild -create-xcframework \
 	-library ../target/aarch64-apple-ios-sim/release/libmls_rs_uniffi_ios.a -headers ./bindings \
 	-library ../target/aarch64-apple-ios/release/libmls_rs_uniffi_ios.a -headers ./bindings \
 	-output "ios/Mobile.xcframework" 

```