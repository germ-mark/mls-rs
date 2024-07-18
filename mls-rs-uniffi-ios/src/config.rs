use mls_rs_core::identity;
use std::fmt::Debug;
use std::sync::Arc;

use mls_rs::{
    client_builder::{self, WithKeyPackageRepo, WithGroupStateStorage},
    error::MlsError,
    storage_provider::in_memory::InMemoryKeyPackageStorage,
    storage_provider::in_memory::InMemoryGroupStateStorage,
    time::MlsTime
};

use mls_rs_crypto_cryptokit::CryptoKitProvider;

use self::group_state::{KeyPackageStorageFfi, GroupStateStorage, GroupStateStorageAdapter, KeyPackageStorageAdapter};
use crate::MlSrsError;

pub mod group_state;

#[derive(Debug, Clone)]
pub(crate) struct ClientKeyPackageStorage(Arc<dyn KeyPackageStorageFfi>);

impl From<Arc<dyn KeyPackageStorageFfi>> for ClientKeyPackageStorage {
    fn from(value: Arc<dyn KeyPackageStorageFfi>) -> Self {
        Self(value)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl mls_rs_core::key_package::KeyPackageStorage for ClientKeyPackageStorage {
    type Error = MlSrsError;

    async fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.0.delete(id.to_vec().await)
    }

    /// Store [`KeyPackageData`] that can be accessed by `id` in the future.
    ///
    /// This function is automatically called whenever a new key package is created.
    async fn insert(&mut self, id: Vec<u8>, pkg: mls_rs_core::key_package::KeyPackageData) -> Result<(), Self::Error> {
        self.0.insert(id, pkg.into()).await
    }

    /// Retrieve [`KeyPackageData`] by its `id`.
    ///
    /// `None` should be returned in the event that no key packages are found
    /// that match `id`.
    async fn get(&self, id: &[u8]) -> Result<Option<mls_rs_core::key_package::KeyPackageData>, Self::Error> {
        self.0.get(id.to_vec()).map(|result| result.map(|option| option.into() ) )
    }
}



#[derive(Debug, Clone)]
pub(crate) struct ClientGroupStorage(Arc<dyn GroupStateStorage>);

impl From<Arc<dyn GroupStateStorage>> for ClientGroupStorage {
    fn from(value: Arc<dyn GroupStateStorage>) -> Self {
        Self(value)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl mls_rs_core::group::GroupStateStorage for ClientGroupStorage {
    type Error = MlSrsError;

    async fn state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.state(group_id.to_vec()).await
    }

    async fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.epoch(group_id.to_vec(), epoch_id).await
    }

    async fn write(
        &mut self,
        state: mls_rs_core::group::GroupState,
        inserts: Vec<mls_rs_core::group::EpochRecord>,
        updates: Vec<mls_rs_core::group::EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.0
            .write(
                state.id,
                state.data,
                inserts.into_iter().map(Into::into).collect(),
                updates.into_iter().map(Into::into).collect(),
            )
            .await
    }

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.0.max_epoch_id(group_id.to_vec()).await
    }
}

pub type UniFFIConfig = client_builder::WithIdentityProvider<
    IdentityProviderStorage,
    client_builder::WithCryptoProvider<
        CryptoKitProvider,
        WithKeyPackageRepo <
            ClientKeyPackageStorage,
            WithGroupStateStorage<ClientGroupStorage, client_builder::BaseConfig>,
        >,
    >,
>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    pub client_keypackage_storage: Arc<dyn KeyPackageStorageFfi>,
    pub group_state_storage: Arc<dyn GroupStateStorage>,
    pub identity_provider_storage: Arc<dyn IdentityProviderFFI>,
    /// Use the ratchet tree extension. If this is false, then you
    /// must supply `ratchet_tree` out of band to clients.
    pub use_ratchet_tree_extension: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_keypackage_storage: Arc::new(
                KeyPackageStorageAdapter::new(InMemoryKeyPackageStorage::new())
                ),
            group_state_storage: Arc::new(GroupStateStorageAdapter::new(
                InMemoryGroupStateStorage::new(),
            )),
            identity_provider_storage: Arc::new(BasicIdentityProviderShim::new()),
            use_ratchet_tree_extension: true,
        }
    }
}

// TODO(mgeisler): turn into an associated function when UniFFI
// supports them: https://github.com/mozilla/uniffi-rs/issues/1074.
/// Create a client config with an in-memory group state storage.
#[uniffi::export]
pub fn client_config_default() -> ClientConfig {
    ClientConfig::default()
}

/// Supported cipher suites.
///
/// This is a subset of the cipher suites found in
/// [`mls_rs::CipherSuite`].
#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum CipherSuite {
    // TODO(mgeisler): add more cipher suites.
    Curve25519ChaCha,
}

impl From<CipherSuite> for mls_rs::CipherSuite {
    fn from(cipher_suite: CipherSuite) -> mls_rs::CipherSuite {
        match cipher_suite {
            CipherSuite::Curve25519ChaCha => mls_rs::CipherSuite::CURVE25519_CHACHA,
        }
    }
}

impl TryFrom<mls_rs::CipherSuite> for CipherSuite {
    type Error = MlSrsError;

    fn try_from(cipher_suite: mls_rs::CipherSuite) -> Result<Self, Self::Error> {
        match cipher_suite {
            mls_rs::CipherSuite::CURVE25519_CHACHA => Ok(CipherSuite::Curve25519ChaCha),
            _ => Err(MlsError::UnsupportedCipherSuite(cipher_suite))?,
        }
    }
}

/// Adapt an IdentityProvider 
/// The default BasicCredential Identity Provider asserts identity equality
/// For Germ, the basic credential is just an anchor into our evolving identity architecture

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct SigningIdentity {
    pub inner: identity::SigningIdentity,
}

impl From<identity::SigningIdentity> for SigningIdentity {
    fn from(inner: identity::SigningIdentity) -> Self {
        Self { inner }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
impl SigningIdentity {
    #[uniffi::constructor]
    pub fn new(
        signature_key_data: Vec<u8>,
        basic_credential: Vec<u8>,
    ) -> Result<Self, MlSrsError> {
        let signing_identity = identity::SigningIdentity::new(
            identity::Credential::Basic(identity::BasicCredential{identifier: basic_credential}),
            signature_key_data.into(),
        );
        Ok( signing_identity.into() )
    }

    pub fn basic_credential(&self) -> Option<Vec<u8>> {
        match self.clone().inner.credential {
            mls_rs::identity::Credential::Basic(basic_credential) => Some(basic_credential.identifier),
            _ => None
        }
    }

    pub fn node_signing_key(&self) -> SignaturePublicKey {
        self.inner.signature_key.clone().into()
    }
}

/// A [`mls_rs::crypto::SignaturePublicKey`] wrapper.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SignaturePublicKey {
    pub bytes: Vec<u8>,
}

impl From<mls_rs::crypto::SignaturePublicKey> for SignaturePublicKey {
    fn from(public_key: mls_rs::crypto::SignaturePublicKey) -> Self {
        Self {
            bytes: public_key.to_vec(),
        }
    }
}

impl From<SignaturePublicKey> for mls_rs::crypto::SignaturePublicKey {
    fn from(public_key: SignaturePublicKey) -> Self {
        Self::new(public_key.bytes)
    }
}

/// A [`mls_rs::crypto::SignatureSecretKey`] wrapper.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SignatureSecretKey {
    pub bytes: Vec<u8>,
}

impl From<mls_rs::crypto::SignatureSecretKey> for SignatureSecretKey {
    fn from(secret_key: mls_rs::crypto::SignatureSecretKey) -> Self {
        Self {
            bytes: secret_key.as_bytes().to_vec(),
        }
    }
}

impl From<SignatureSecretKey> for mls_rs::crypto::SignatureSecretKey {
    fn from(secret_key: SignatureSecretKey) -> Self {
        Self::new(secret_key.bytes)
    }
}

/// A ([`SignaturePublicKey`], [`SignatureSecretKey`]) pair.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SignatureKeypair {
    pub cipher_suite: CipherSuite,
    pub public_key: SignaturePublicKey,
    pub secret_key: SignatureSecretKey,
}

/// A [`mls_rs::ExtensionList`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct ExtensionList {
    _inner: mls_rs::ExtensionList,
}

impl From<mls_rs::ExtensionList> for ExtensionList {
    fn from(inner: mls_rs::ExtensionList) -> Self {
        Self { _inner: inner }
    }
}

/// A [`mls_rs::Extension`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct Extension {
    _inner: mls_rs::Extension,
}

impl From<mls_rs::Extension> for Extension {
    fn from(inner: mls_rs::Extension) -> Self {
        Self { _inner: inner }
    }
}

/// Identity system that can be used to validate a
/// [`SigningIdentity`](mls-rs-core::identity::SigningIdentity)
#[cfg_attr(mls_build_async, uniffi::export(with_foreign))]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(not(mls_build_async), uniffi::export(with_foreign))]
pub trait IdentityProviderFFI: Send + Sync + Debug {

    /// Determine if `signing_identity` is valid for a group member.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](mls-rs-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    async fn validate_member(
        &self,
        signing_identity: Arc<SigningIdentity>,
        timestamp: Option<u64>,
        extensions: Option<Arc<ExtensionList>>,
    ) -> Result<(), MlSrsError>;

    /// Determine if `signing_identity` is valid for an external sender in
    /// the ExternalSendersExtension stored in the group context.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](mls-rs-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    async fn validate_external_sender(
        &self,
        signing_identity: Arc<SigningIdentity>,
        timestamp: Option<u64>,
        extensions: Option<Arc<ExtensionList>>,
    ) -> Result<(), MlSrsError>;

    /// A unique identifier for `signing_identity`.
    ///
    /// The MLS protocol requires that each member of a group has a unique
    /// set of identifiers according to the application.
    async fn identity(
        &self,
        signing_identity: Arc<SigningIdentity>,
        extensions: Arc<ExtensionList>,
    ) -> Result<Vec<u8>, MlSrsError>;

    /// Determines if `successor` can remove `predecessor` as part of an external commit.
    ///
    /// The MLS protocol allows for removal of an existing member when adding a
    /// new member via external commit. This function determines if a removal
    /// should be allowed by providing the target member to be removed as
    /// `predecessor` and the new member as `successor`.
    async fn valid_successor(
        &self,
        predecessor: Arc<SigningIdentity>,
        successor: Arc<SigningIdentity>,
        extensions: Arc<ExtensionList>,
    ) -> Result<bool, MlSrsError>;

    /// Credential types that are supported by this provider.
    fn supported_types(&self) -> Vec<u16>;
}


#[derive(Debug, Clone)]
pub(crate) struct IdentityProviderStorage(Arc<dyn IdentityProviderFFI>);

impl From<Arc<dyn IdentityProviderFFI>> for IdentityProviderStorage {
    fn from(value: Arc<dyn IdentityProviderFFI>) -> Self {
        Self(value)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl mls_rs_core::identity::IdentityProvider for IdentityProviderStorage {
    type Error = MlSrsError;

    async fn validate_member(
        &self,
        signing_identity: &identity::SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&mls_rs::ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.0.validate_member(
            Arc::new( signing_identity.clone().into() ),
            timestamp.map(|t| t.seconds_since_epoch()),
            extensions.map(|e| Arc::new( e.clone().into() ))
        )
    }

    /// Determine if `signing_identity` is valid for an external sender in
    /// the ExternalSendersExtension stored in the group context.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](mls-rs-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    fn validate_external_sender(
        &self,
        signing_identity: &identity::SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&mls_rs::ExtensionList>,
    ) -> Result<(), MlSrsError> {
        self.0.validate_external_sender(
            Arc::new( signing_identity.clone().into() ),
            timestamp.map(|t| t.seconds_since_epoch()),
            extensions.map(|e| Arc::new( e.clone().into() ))
        )
    }

    /// A unique identifier for `signing_identity`.
    ///
    /// The MLS protocol requires that each member of a group has a unique
    /// set of identifiers according to the application.
    fn identity(
        &self,
        signing_identity: &identity::SigningIdentity,
        extensions: &mls_rs::ExtensionList,
    ) -> Result<Vec<u8>, MlSrsError> {
        self.0.identity(
            Arc::new( signing_identity.clone().into() ),
            Arc::new( extensions.clone().into() )
        )
    }

    /// Determines if `successor` can remove `predecessor` as part of an external commit.
    ///
    /// The MLS protocol allows for removal of an existing member when adding a
    /// new member via external commit. This function determines if a removal
    /// should be allowed by providing the target member to be removed as
    /// `predecessor` and the new member as `successor`.
    fn valid_successor(
        &self,
        predecessor: &identity::SigningIdentity,
        successor: &identity::SigningIdentity,
        extensions: &mls_rs::ExtensionList,
    ) -> Result<bool, MlSrsError> {
        self.0.valid_successor(
            Arc::new( predecessor.clone().into() ),
            Arc::new( successor.clone().into() ), 
            Arc::new( extensions.clone().into() )
        )
    }

    fn supported_types(&self) -> Vec<mls_rs::identity::CredentialType> {
        self.0.supported_types()
            .iter()
            .map(|n| mls_rs::identity::CredentialType::new(*n))
            .collect()
    }
}

//Instead of an adapter, just a simple default shim
#[derive (Debug)]
struct BasicIdentityProviderShim {}

impl BasicIdentityProviderShim {
    fn new() -> Self {
        Self {}
    }
}

impl IdentityProviderFFI for BasicIdentityProviderShim {

    fn validate_member(
        &self,
        _: Arc<SigningIdentity>,
        _: Option<u64>,
        _: Option<Arc<ExtensionList>>,
    ) -> Result<(), MlSrsError> {
        Ok(())
    }

    fn validate_external_sender(
        &self,
        _: Arc<SigningIdentity>,
        _: Option<u64>,
        _: Option<Arc<ExtensionList>>,
    ) -> Result<(), MlSrsError> {
        Ok(())
    }

    fn identity(
        &self,
        signing_identity: Arc<SigningIdentity>,
        _: Arc<ExtensionList>,
    ) -> Result<Vec<u8>, MlSrsError> {
        let credential = signing_identity.basic_credential();
        match credential {
            Some(credential) => Ok(credential),
            None => Err(MlSrsError::MissingBasicCredential)
        }
    }


    fn valid_successor(
        &self,
        _: Arc<SigningIdentity>,
        _: Arc<SigningIdentity>,
        _: Arc<ExtensionList>,
    ) -> Result<bool, MlSrsError> {
        Ok(true)
    }

    /// Credential types that are supported by this provider.
    fn supported_types(&self) -> Vec<u16> {
        vec![1]
    }
}
