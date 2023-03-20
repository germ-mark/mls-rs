use std::ops::Deref;

use async_trait::async_trait;
use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroizing;

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Wrapper type that holds a pre-shared key value and zeroizes on drop.
pub struct PreSharedKey(
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")] Zeroizing<Vec<u8>>,
);

impl PreSharedKey {
    /// Create a new PreSharedKey.
    pub fn new(data: Vec<u8>) -> Self {
        PreSharedKey(Zeroizing::new(data))
    }

    /// Raw byte value.
    pub fn raw_value(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PreSharedKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<Zeroizing<Vec<u8>>> for PreSharedKey {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PreSharedKey {
    fn as_ref(&self) -> &[u8] {
        self.raw_value()
    }
}

impl Deref for PreSharedKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.raw_value()
    }
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// An external pre-shared key identifier.
pub struct ExternalPskId(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    Vec<u8>,
);

impl ExternalPskId {
    pub fn new(id_data: Vec<u8>) -> Self {
        Self(id_data)
    }
}

impl AsRef<[u8]> for ExternalPskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ExternalPskId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ExternalPskId {
    fn from(value: Vec<u8>) -> Self {
        ExternalPskId(value)
    }
}

#[async_trait]
/// Storage trait to maintain a set of pre-shared key values.
pub trait PreSharedKeyStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get a pre-shared key by [`ExternalPskId`](ExternalPskId).
    ///
    /// `None` should be returned if a pre-shared key can not be found for `id`.
    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error>;
}
