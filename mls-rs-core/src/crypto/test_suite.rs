// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use itertools::Itertools;

use crate::crypto::HpkeContextR;

use super::{
    CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkeContextS, HpkePublicKey, HpkeSecretKey,
};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/crypto_provider.json"
);

#[cfg(any(target_arch = "wasm32", not(feature = "std")))]
const SERIALIZED_TEST_SUITES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/crypto_provider.json"
));

pub const DATA_SIZES: [usize; 5] = [0, 1, 16, 123, 2000];

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct TestSuite {
    cipher_suite: u16,
    #[serde(default)]
    signature_tests: Vec<SignatureTestCase>,
    #[serde(default)]
    aead_tests: Vec<AeadTestCase>,
    #[serde(default)]
    hpke_tests: HpkeTestCases,
    #[serde(default)]
    hkdf_tests: Vec<HkdfTestCase>,
    #[serde(default)]
    mac_tests: Vec<MacTestCase>,
}

#[cfg(all(not(mls_build_async), not(target_arch = "wasm32"), feature = "std"))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn generate_tests<C: CryptoProvider>(crypto: &C) {
    for cs in crypto.supported_cipher_suites() {
        crypto.cipher_suite_provider(cs).unwrap();
    }

    let mut test_suites = create_or_load_tests(crypto);

    for test_suite in test_suites.iter_mut() {
        let cs = test_suite.cipher_suite.into();
        let cs = crypto.cipher_suite_provider(cs).unwrap();

        test_suite.signature_tests = generate_signature_tests(&cs);
        test_suite.hpke_tests = generate_hpke_tests(&cs);
        test_suite.hkdf_tests = generate_hkdf_tests(&cs);
    }

    std::fs::write(PATH, serde_json::to_string_pretty(&test_suites).unwrap()).unwrap();
}

#[cfg(all(not(mls_build_async), not(target_arch = "wasm32"), feature = "std"))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn create_or_load_tests<C: CryptoProvider>(crypto: &C) -> Vec<TestSuite> {
    if std::path::Path::new(PATH).exists() {
        serde_json::from_slice(&std::fs::read(PATH).unwrap()).unwrap()
    } else {
        crypto
            .supported_cipher_suites()
            .into_iter()
            .map(|cipher_suite| TestSuite {
                cipher_suite: cipher_suite.into(),
                ..Default::default()
            })
            .collect()
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub async fn verify_tests<C: CryptoProvider>(crypto: &C) {
    #[cfg(any(target_arch = "wasm32", not(feature = "std")))]
    let test_suites: Vec<TestSuite> = serde_json::from_slice(SERIALIZED_TEST_SUITES).unwrap();

    #[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
    let test_suites: Vec<TestSuite> =
        serde_json::from_slice(&std::fs::read(PATH).unwrap()).unwrap();

    for test_suite in test_suites {
        let cs = test_suite.cipher_suite.into();
        let Some(cs) = crypto.cipher_suite_provider(cs) else {
            continue;
        };

        verify_hkdf_tests(&cs, test_suite.hkdf_tests).await;
        verify_aead_tests(&cs, test_suite.aead_tests).await;
        verify_mac_tests(&cs, test_suite.mac_tests).await;
        verify_hpke_tests(&cs, test_suite.hpke_tests).await;
        verify_signature_tests(&cs, test_suite.signature_tests).await;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SignatureTestCase {
    #[serde(with = "hex::serde")]
    secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    public: Vec<u8>,
    #[serde(with = "hex::serde")]
    data: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_signature_tests<C: CipherSuiteProvider>(
    cs: &C,
    test_cases: Vec<SignatureTestCase>,
) {
    // Checks that `cs` can sign and verify
    let generated = generate_signature_tests(cs).await;

    for test_case in test_cases.into_iter().chain(generated) {
        let public = test_case.public.into();

        // Checks that `cs` can verify signatures generated by itself and another implementation
        cs.verify(&public, &test_case.signature, &test_case.data)
            .await
            .unwrap();

        let secret = test_case.secret.into();

        // Checks that `cs` can parse a secret key generated by itself and another implementation
        let derived = cs.signature_key_derive_public(&secret).await.unwrap();

        cs.sign(&secret, b"hello world").await.unwrap();

        assert_eq!(derived, public);
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn generate_signature_tests<C: CipherSuiteProvider>(cs: &C) -> Vec<SignatureTestCase> {
    let mut tests = Vec::new();

    for data_size in DATA_SIZES {
        let data = cs.random_bytes_vec(data_size).unwrap();
        let (secret, public) = cs.signature_key_generate().await.unwrap();
        let signature = cs.sign(&secret, &data).await.unwrap();

        tests.push(SignatureTestCase {
            secret: secret.to_vec(),
            public: public.to_vec(),
            data,
            signature,
        });
    }

    tests
}

// Test vectors from the RFC
#[derive(serde::Deserialize, serde::Serialize)]
struct AeadTestCase {
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub iv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_aead_tests<C: CipherSuiteProvider>(cs: &C, test_cases: Vec<AeadTestCase>) {
    for case in test_cases {
        let ciphertext = cs
            .aead_seal(&case.key, &case.pt, Some(&case.aad), &case.iv)
            .await
            .unwrap();

        assert_eq!(ciphertext, case.ct);

        let plaintext = cs
            .aead_open(&case.key, &ciphertext, Some(&case.aad), &case.iv)
            .await
            .unwrap();

        assert_eq!(plaintext.to_vec(), case.pt);
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct HpkeTestCases {
    #[serde(with = "hex::serde")]
    ikm: Vec<u8>,
    #[serde(with = "hex::serde")]
    secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    public: Vec<u8>,

    seal_tests: Vec<HpkeSealTestCase>,
    export_tests: Vec<HpkeExportTestCase>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HpkeSealTestCase {
    #[serde(with = "hex::serde")]
    plaintext: Vec<u8>,
    #[serde(with = "hex::serde")]
    info: Vec<u8>,
    #[serde(with = "hex::serde")]
    aad: Vec<u8>,

    // Seal and open
    #[serde(with = "hex::serde")]
    sealed_kem_output: Vec<u8>,
    #[serde(with = "hex::serde")]
    sealed_ciphertext: Vec<u8>,

    // Setup s and r
    #[serde(with = "hex::serde")]
    setup_s_kem_output: Vec<u8>,
    #[serde(with = "hex::serde")]
    setup_s_ciphertext: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HpkeExportTestCase {
    #[serde(with = "hex::serde")]
    info: Vec<u8>,
    #[serde(with = "hex::serde")]
    kem_output: Vec<u8>,

    #[serde(with = "hex::serde")]
    exporter_context: Vec<u8>,
    exported_len: usize,
    #[serde(with = "hex::serde")]
    exported: Vec<u8>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_hpke_tests<C: CipherSuiteProvider>(cs: &C, test_cases: HpkeTestCases) {
    let generated = generate_hpke_tests(cs).await;
    verify_hpke_test(cs, generated).await;
    verify_hpke_test(cs, test_cases).await;
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_hpke_test<C: CipherSuiteProvider>(cs: &C, test_cases: HpkeTestCases) {
    let (secret, public) = cs.kem_derive(&test_cases.ikm).await.unwrap();

    assert_eq!(&secret, &test_cases.secret.into());
    assert_eq!(&public, &test_cases.public.into());

    for test in test_cases.seal_tests {
        let ct = HpkeCiphertext {
            kem_output: test.sealed_kem_output.clone(),
            ciphertext: test.sealed_ciphertext.clone(),
        };

        test_open_ciphertext(cs, &secret, &public, &ct, &test).await;

        let ct = HpkeCiphertext {
            kem_output: test.setup_s_kem_output.clone(),
            ciphertext: test.setup_s_ciphertext.clone(),
        };

        test_open_ciphertext(cs, &secret, &public, &ct, &test).await;
    }

    for test in test_cases.export_tests {
        let context_r = cs
            .hpke_setup_r(&test.kem_output, &secret, &public, &test.info)
            .await
            .unwrap();

        let exported = context_r
            .export(&test.exporter_context, test.exported_len)
            .await
            .unwrap();

        assert_eq!(exported, test.exported);
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn test_open_ciphertext<C: CipherSuiteProvider>(
    cs: &C,
    secret: &HpkeSecretKey,
    public: &HpkePublicKey,
    ct: &HpkeCiphertext,
    test: &HpkeSealTestCase,
) {
    let aad = (!test.aad.is_empty()).then_some(test.aad.as_slice());
    let opened = cs
        .hpke_open(ct, secret, public, &test.info, aad)
        .await
        .unwrap();
    assert_eq!(&opened, &test.plaintext);

    let mut context_r = cs
        .hpke_setup_r(&ct.kem_output, secret, public, &test.info)
        .await
        .unwrap();

    let opened = context_r.open(aad, &ct.ciphertext).await.unwrap();
    assert_eq!(&opened, &test.plaintext);
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn generate_hpke_tests<C: CipherSuiteProvider>(cs: &C) -> HpkeTestCases {
    let ikm = cs.random_bytes_vec(cs.kdf_extract_size()).unwrap();
    let (secret, public) = cs.kem_derive(&ikm).await.unwrap();

    let sizes_iter = DATA_SIZES.iter().copied();

    let mut seal_tests = Vec::new();

    for ((pt_size, info_size), aad_size) in sizes_iter
        .clone()
        .skip(1)
        .cartesian_product(sizes_iter.clone())
        .cartesian_product(sizes_iter.clone())
    {
        let plaintext = cs.random_bytes_vec(pt_size).unwrap();
        let info = cs.random_bytes_vec(info_size).unwrap();
        let aad = cs.random_bytes_vec(aad_size).unwrap();

        let sealed = cs
            .hpke_seal(&public, &info, (aad_size > 0).then_some(&aad), &plaintext)
            .await
            .unwrap();

        let (setup_s_kem_output, mut context_s) = cs.hpke_setup_s(&public, &info).await.unwrap();

        let setup_s_ciphertext = context_s
            .seal((aad_size > 0).then_some(&aad), &plaintext)
            .await
            .unwrap();

        seal_tests.push(HpkeSealTestCase {
            plaintext,
            info,
            aad,
            sealed_kem_output: sealed.kem_output,
            sealed_ciphertext: sealed.ciphertext,
            setup_s_kem_output,
            setup_s_ciphertext,
        })
    }

    let mut export_tests = Vec::new();

    for ((context_len, exported_len), info_size) in sizes_iter
        .clone()
        .cartesian_product(sizes_iter.clone().skip(1))
        .cartesian_product(sizes_iter)
    {
        let exporter_context = cs.random_bytes_vec(context_len).unwrap();
        let info = cs.random_bytes_vec(info_size).unwrap();
        let (kem_output, context) = cs.hpke_setup_s(&public, &info).await.unwrap();

        let exported = context
            .export(&exporter_context, exported_len)
            .await
            .unwrap();

        export_tests.push(HpkeExportTestCase {
            info,
            kem_output,
            exporter_context,
            exported_len,
            exported,
        });
    }

    HpkeTestCases {
        ikm,
        secret: secret.to_vec(),
        public: public.to_vec(),
        seal_tests,
        export_tests,
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct HkdfTestCase {
    #[serde(with = "hex::serde")]
    pub ikm: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub salt: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub info: Vec<u8>,
    pub len: usize,
    #[serde(with = "hex::serde")]
    pub prk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub okm: Vec<u8>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_hkdf_tests<C: CipherSuiteProvider>(cs: &C, test_cases: Vec<HkdfTestCase>) {
    for case in test_cases {
        let extracted = cs.kdf_extract(&case.salt, &case.ikm).await.unwrap();

        assert_eq!(extracted.to_vec(), case.prk);

        let expanded = cs
            .kdf_expand(&case.prk, &case.info, case.len)
            .await
            .unwrap();

        assert_eq!(expanded.to_vec(), case.okm);
    }
}

#[cfg(all(not(mls_build_async), not(target_arch = "wasm32"), feature = "std"))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn generate_hkdf_tests<C: CipherSuiteProvider>(cs: &C) -> Vec<HkdfTestCase> {
    let iter = DATA_SIZES.iter().copied();

    let iter = iter
        .clone()
        .skip(1)
        .cartesian_product(iter.clone())
        .cartesian_product(iter.clone())
        .cartesian_product(iter.skip(1));

    iter.map(|(((ikm_size, salt_size), info_size), len)| {
        let ikm = cs.random_bytes_vec(ikm_size).unwrap();
        let salt = cs.random_bytes_vec(salt_size).unwrap();
        let info = cs.random_bytes_vec(info_size).unwrap();

        let prk = cs.kdf_extract(&salt, &ikm).unwrap().to_vec();
        let okm = cs.kdf_expand(&prk, &info, len).unwrap().to_vec();

        HkdfTestCase {
            ikm,
            salt,
            info,
            len,
            prk,
            okm,
        }
    })
    .collect()
}

// Test vectors from RFC 4231
#[derive(serde::Deserialize, serde::Serialize)]
struct MacTestCase {
    #[serde(with = "hex::serde")]
    key: Vec<u8>,
    #[serde(with = "hex::serde")]
    data: Vec<u8>,
    #[serde(with = "hex::serde")]
    tag: Vec<u8>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn verify_mac_tests<C: CipherSuiteProvider>(cs: &C, test_cases: Vec<MacTestCase>) {
    for case in test_cases {
        let computed = cs.mac(&case.key, &case.data).await.unwrap();
        assert_eq!(computed, case.tag);
    }
}
