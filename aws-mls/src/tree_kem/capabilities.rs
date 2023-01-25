use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    cipher_suite::MaybeCipherSuite, extension::ExtensionType, group::proposal::ProposalType,
    identity::CredentialType, protocol_version::MaybeProtocolVersion,
};

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Capabilities {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub protocol_versions: Vec<MaybeProtocolVersion>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub cipher_suites: Vec<MaybeCipherSuite>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub credentials: Vec<CredentialType>,
}

#[cfg(any(feature = "benchmark", test))]
impl Default for Capabilities {
    fn default() -> Self {
        use crate::cipher_suite::CipherSuite;
        use crate::identity::BasicCredential;
        use crate::protocol_version::ProtocolVersion;

        Self {
            protocol_versions: vec![MaybeProtocolVersion::from(ProtocolVersion::Mls10)],
            cipher_suites: CipherSuite::all().map(MaybeCipherSuite::from).collect(),
            extensions: Default::default(),
            proposals: Default::default(),
            credentials: vec![BasicCredential::credential_type()],
        }
    }
}