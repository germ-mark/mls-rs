# iOS XCFramework
Build toolchain to generate a XCFramework for mls-rs for an iOS app, using uniffi to generate bindings

# Scripted
1. Ensure you add the ios targets to Rust
2. the script at `scripts/buildIos.swift` automates the following steps

# Manual fixes
1. Currently uniffi header has a bug that inserts a misplaced throw keyword in the definition of `Message.init(bytes: )`
(The throws keyword belongs in the function signature, not the try call to rustCallWithError)
```
public convenience init(bytes: Data) {
    let pointer = throws try rustCallWithError(FfiConverterTypeMlSrsError.lift) {
    uniffi_mls_rs_uniffi_ios_fn_constructor_message_new(
        FfiConverterData.lower(bytes),$0
    )
}
```
2. Uniffi also complains that it is unable to find swift format, but we can just run `swift format` on the output to lint it
3. (Synthesized) Conformance to `Codable, Sendable` should be declared in the file where `KeyPackageData` is declared, so we should edit the generated header file to add the conformances. To help remind us, there is a test that will fail if KeyPackageData is not marked Codable


# Manual Steps:
(preamble - run once)
Add ios targets to Rust:
```
rustup target add aarch64-apple-ios-sim aarch64-apple-ios x86_64-apple-ios
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
 	-output "ios/MLSrs.xcframework" 

```