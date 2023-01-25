use super::*;
use crate::hash_reference::{HashReference, HashReferenceError};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProposalRef(HashReference);

impl Deref for ProposalRef {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProposalRef {
    pub(crate) fn from_content<CS: CipherSuiteProvider>(
        cipher_suite_provider: &CS,
        content: &MLSAuthenticatedContent,
    ) -> Result<Self, HashReferenceError> {
        Ok(ProposalRef(HashReference::compute(
            &content.tls_serialize_detached()?,
            b"MLS 1.0 Proposal Reference",
            cipher_suite_provider,
        )?))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::group::test_utils::{random_bytes, TEST_GROUP};

    pub fn auth_content_from_proposal<S>(proposal: Proposal, sender: S) -> MLSAuthenticatedContent
    where
        S: Into<Sender>,
    {
        MLSAuthenticatedContent {
            wire_format: WireFormat::Plain,
            content: MLSContent {
                group_id: TEST_GROUP.to_vec(),
                epoch: 0,
                sender: sender.into(),
                authenticated_data: vec![],
                content: Content::Proposal(proposal),
            },
            auth: MLSContentAuthData {
                signature: MessageSignature::from(random_bytes(128)),
                confirmation_tag: None,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::test_utils::auth_content_from_proposal;
    use super::*;
    use crate::{
        extension::RequiredCapabilitiesExt,
        key_package::test_utils::test_key_package,
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider,
        },
        tree_kem::leaf_node::test_utils::get_basic_test_node,
    };

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn get_test_extension_list() -> ExtensionList<GroupContextExtension> {
        let test_extension = RequiredCapabilitiesExt {
            extensions: vec![42],
            proposals: Default::default(),
            credentials: vec![],
        };

        let mut extension_list = ExtensionList::new();
        extension_list.set_extension(test_extension).unwrap();

        extension_list
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    async fn generate_proposal_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let sender = LeafIndex(0);

            let add = auth_content_from_proposal(
                Proposal::Add(AddProposal {
                    key_package: test_key_package(protocol_version, cipher_suite, "alice").await,
                }),
                sender,
            );

            let update = auth_content_from_proposal(
                Proposal::Update(UpdateProposal {
                    leaf_node: get_basic_test_node(cipher_suite, "foo").await,
                }),
                sender,
            );

            let remove = auth_content_from_proposal(
                Proposal::Remove(RemoveProposal {
                    to_remove: LeafIndex(1),
                }),
                sender,
            );

            let group_context_ext = auth_content_from_proposal(
                Proposal::GroupContextExtensions(get_test_extension_list()),
                sender,
            );

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: add.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_content(&cipher_suite_provider, &add)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: update.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_content(&cipher_suite_provider, &update)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: remove.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_content(&cipher_suite_provider, &remove)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: group_context_ext.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_content(&cipher_suite_provider, &group_context_ext)
                    .unwrap()
                    .to_vec(),
            });
        }

        test_cases
    }

    async fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(proposal_ref, generate_proposal_test_cases().await)
    }

    #[futures_test::test]
    async fn test_proposal_ref() {
        let test_cases = load_test_cases().await;

        for one_case in test_cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                continue;
            };

            let proposal_content =
                MLSAuthenticatedContent::tls_deserialize(&mut one_case.input.as_slice()).unwrap();

            let proposal_ref = ProposalRef::from_content(&cs_provider, &proposal_content).unwrap();

            let expected_out = ProposalRef(HashReference::from(one_case.output));

            assert_eq!(expected_out, proposal_ref);
        }
    }
}