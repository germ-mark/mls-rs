// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! UniFFI-compatible wrapper around mls-rs.
//!
//! This is an opinionated UniFFI-compatible wrapper around mls-rs:
//!
//! - Opinionated: the wrapper removes some flexiblity from mls-rs and
//!   focuses on exposing the minimum functionality necessary for
//!   messaging apps.
//!
//! - UniFFI-compatible: the wrapper exposes types annotated to be
//!   used with [UniFFI]. This makes it possible to automatically
//!   generate a Kotlin, Swift, ... code which calls into the Rust
//!   code.
//!
//! [UniFFI]: https://mozilla.github.io/uniffi-rs/

mod config;

use std::sync::Arc;

pub use config::ClientConfig;
use config::UniFFIConfig;

#[cfg(not(mls_build_async))]
use std::sync::Mutex;
#[cfg(mls_build_async)]
use tokio::sync::Mutex;

use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::group;
use mls_rs::identity::basic;
use mls_rs::mls_rules;
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_core::identity;
use mls_rs_core::identity::{BasicCredential, IdentityProvider};
//use mls_rs_crypto_openssl::OpensslCryptoProvider;
use mls_rs_crypto_cryptokit::CryptoKitProvider;
use mls_rs::mls_rs_codec::MlsDecode;

uniffi::setup_scaffolding!();

/// Unwrap the `Arc` if there is a single strong reference, otherwise
/// clone the inner value.
fn arc_unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    // TODO(mgeisler): use Arc::unwrap_or_clone from Rust 1.76.
    match Arc::try_unwrap(arc) {
        Ok(t) => t,
        Err(arc) => (*arc).clone(),
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum MlSrsError {
    #[error("A mls-rs error occurred: {inner}")]
    MlsError {
        #[from]
        inner: mls_rs::error::MlsError,
    },
    #[error("An unknown error occurred: {inner}")]
    AnyError {
        #[from]
        inner: mls_rs::error::AnyError,
    },
    #[error("A data encoding error occurred: {inner}")]
    MlsCodecError {
        #[from]
        inner: mls_rs_core::mls_rs_codec::Error,
    },
    #[error("Unexpected callback error in UniFFI: {inner}")]
    UnexpectedCallbackError {
        #[from]
        inner: uniffi::UnexpectedUniFFICallbackError,
    },
    #[error("Unexpected message format")]
    UnexpecteMessageFormat,
    #[error("Inconsistent Optional Parameters")]
    InconsistentOptionalParameters
}

impl IntoAnyError for MlSrsError {}

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
    cipher_suite: CipherSuite,
    public_key: SignaturePublicKey,
    secret_key: SignatureSecretKey,
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

/// A [`mls_rs::Group`] and [`mls_rs::group::NewMemberInfo`] wrapper.
#[derive(uniffi::Record, Clone)]
pub struct JoinInfo {
    /// The group that was joined.
    pub group: Arc<Group>,
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub group_info_extensions: Arc<ExtensionList>,
}

#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum ProtocolVersion {
    /// MLS version 1.0.
    Mls10,
}

impl TryFrom<mls_rs::ProtocolVersion> for ProtocolVersion {
    type Error = MlSrsError;

    fn try_from(version: mls_rs::ProtocolVersion) -> Result<Self, Self::Error> {
        match version {
            mls_rs::ProtocolVersion::MLS_10 => Ok(ProtocolVersion::Mls10),
            _ => Err(MlsError::UnsupportedProtocolVersion(version))?,
        }
    }
}

/// A [`mls_rs::MlsMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Message {
    inner: mls_rs::MlsMessage,
}

#[uniffi::export]
impl Message {
    #[uniffi::constructor]
     pub fn new(bytes: &[u8]) ->  Result<Self, MlSrsError> {
        let inner = mls_rs::MlsMessage::from_bytes(bytes)
            .map_err(|err| err.into_any_error())?;
        Ok( Self { inner } )
     }

     pub fn to_bytes(&self) -> Result<Vec<u8>, MlSrsError> {
        let result = self.inner.to_bytes()
            .map_err(|err| err.into_any_error())?;
        Ok(result)
     }

    pub fn group_id(&self) -> Option<Vec<u8>> {
        self.inner.group_id().map(|id| id.to_vec())
    }

    pub fn wire_format(&self) -> u16 {
        self.inner.wire_format() as u16
    }

    pub fn epoch(&self) -> Option<u64> {
        self.inner.epoch()
    }

    pub fn private_message_content_type(&self) -> Option<u8> {
        self.inner.private_message_content_type()
    }
}

impl From<mls_rs::MlsMessage> for Message {
    fn from(inner: mls_rs::MlsMessage) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct Proposal {
    _inner: mls_rs::group::proposal::Proposal,
}

impl From<mls_rs::group::proposal::Proposal> for Proposal {
    fn from(inner: mls_rs::group::proposal::Proposal) -> Self {
        Self { _inner: inner }
    }
}

#[uniffi::export]
impl Proposal {
    fn proposal_type(&self) -> u16 {
        self._inner.proposal_type().raw_value()
    }
}

/// Update of a member due to a commit.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MemberUpdate {
    pub prior: Arc<SigningIdentity>,
    pub new: Arc<SigningIdentity>,
}

/// A set of roster updates due to a commit.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RosterUpdate {
    pub added: Vec<Arc<SigningIdentity>>,
    pub removed: Vec<Arc<SigningIdentity>>,
    pub updated: Vec<MemberUpdate>,
}

impl RosterUpdate {
    // This is an associated function because it felt wrong to hide
    // the clones in an `impl From<&mls_rs::identity::RosterUpdate>`.
    fn new(roster_update: &mls_rs::identity::RosterUpdate) -> Self {
        let added = roster_update
            .added()
            .iter()
            .map(|member| Arc::new(member.signing_identity.clone().into()))
            .collect();
        let removed = roster_update
            .removed()
            .iter()
            .map(|member| Arc::new(member.signing_identity.clone().into()))
            .collect();
        let updated = roster_update
            .updated()
            .iter()
            .map(|update| MemberUpdate {
                prior: Arc::new(update.prior.signing_identity.clone().into()),
                new: Arc::new(update.new.signing_identity.clone().into()),
            })
            .collect();
        RosterUpdate {
            added,
            removed,
            updated,
        }
    }
}

/// A [`mls_rs::group::ReceivedMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ReceivedMessage {
    /// A decrypted application message.
    ///
    /// The encoding of the data in the message is
    /// application-specific and is not determined by MLS.
    ApplicationMessage {
        sender: Arc<SigningIdentity>,
        data: Vec<u8>,
        authenticated_data: Vec<u8>
    },

    /// A new commit was processed creating a new group state.
    Commit {
        committer: Arc<SigningIdentity>,
        roster_update: RosterUpdate,
        authenticated_data: Vec<u8>
    },

    // TODO(mgeisler): rename to `Proposal` when
    // https://github.com/awslabs/mls-rs/issues/98 is fixed.
    /// A proposal was received.
    ReceivedProposal {
        sender: Arc<SigningIdentity>,
        proposal: Arc<Proposal>,
        authenticated_data: Vec<u8>
    },

    /// Validated GroupInfo object.
    GroupInfo,
    /// Validated welcome message.
    Welcome,
    /// Validated key package.
    KeyPackage,
}

//MARK: (MMX) added objects
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MLSMember {
    pub index: u32,
    /// Current identity public key and credential of this member.
    pub signing_identity: Arc<SigningIdentity>
}

impl From<mls_rs::group::Member> for MLSMember {
    fn from(inner: mls_rs::group::Member) -> Self {
        Self { 
            index: inner.index,
            signing_identity: Arc::new(inner.signing_identity.clone().into())
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ReceivedUpdate {
    pub epoch: u64, //which epoch was this received for? determines if we convert to a replace
    pub leaf_index: u32, //filling this outside, but should be able to determine this inside when processing an update
    pub encoded_update: Vec<u8> //mls_encoded UpdateProposal object containing a leaf_node
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

/// Generate a MLS signature keypair.
///
/// This will use the default mls-lite crypto provider.
///
/// See [`mls_rs::CipherSuiteProvider::signature_key_generate`]
/// for details.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
pub async fn generate_signature_keypair(
    cipher_suite: CipherSuite,
) -> Result<SignatureKeypair, MlSrsError> {
    let crypto_provider = mls_rs_crypto_cryptokit::CryptoKitProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cipher_suite.into())
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite.into()))?;

    let (secret_key, public_key) = cipher_suite_provider
        .signature_key_generate()
        .await
        .map_err(|err| MlsError::CryptoProviderError(err.into_any_error()))?;

    Ok(SignatureKeypair {
        cipher_suite,
        public_key: public_key.into(),
        secret_key: secret_key.into(),
    })
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Client {
    inner: mls_rs::client::Client<UniFFIConfig>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
impl Client {
    /// Create a new client.
    ///
    /// The user is identified by `id`, which will be used to create a
    /// basic credential together with the signature keypair.
    ///
    /// See [`mls_rs::Client::builder`] for details.
    #[uniffi::constructor]
    pub fn new(
        id: Vec<u8>,
        signature_keypair: SignatureKeypair,
        client_config: ClientConfig,
    ) -> Self {
        let cipher_suite = signature_keypair.cipher_suite;
        let public_key = signature_keypair.public_key;
        let secret_key = signature_keypair.secret_key;
        let crypto_provider = CryptoKitProvider::default();
        let basic_credential = BasicCredential::new(id);
        let signing_identity =
            identity::SigningIdentity::new(basic_credential.into_credential(), public_key.into());
        let commit_options = mls_rules::CommitOptions::default()
            .with_ratchet_tree_extension(client_config.use_ratchet_tree_extension)
            .with_single_welcome_message(true);
        let encryption_options =  mls_rules::EncryptionOptions::new(
            true, //encrypt control messages
            mls_rs::client_builder::PaddingMode::StepFunction
        );
        let mls_rules = mls_rules::DefaultMlsRules::new()
            .with_commit_options(commit_options)
            .with_encryption_options(encryption_options);
        let client = mls_rs::Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(basic::BasicIdentityProvider::new())
            .signing_identity(signing_identity, secret_key.into(), cipher_suite.into())
            .key_package_repo(client_config.client_keypackage_storage.into())
            .group_state_storage(client_config.group_state_storage.into())
            .mls_rules(mls_rules)
            .build();

        Client { inner: client }
    }

    /// Generate a new key package for this client.
    ///
    /// The key package is represented in is MLS message form. It is
    /// needed when joining a group and can be published to a server
    /// so other clients can look it up.
    ///
    /// See [`mls_rs::Client::generate_key_package_message`] for
    /// details.
    pub async fn generate_key_package_message(&self) -> Result<Message, MlSrsError> {
        let message = self.inner.generate_key_package_message().await?;
        Ok(message.into())
    }

    pub fn signing_identity(&self) -> Result<Arc<SigningIdentity>, MlSrsError> {
        let (signing_identity, _) = self.inner.signing_identity()?;
        Ok(Arc::new(signing_identity.clone().into()))
    }

    /// Create and immediately join a new group.
    ///
    /// If a group ID is not given, the underlying library will create
    /// a unique ID for you.
    ///
    /// See [`mls_rs::Client::create_group`] and
    /// [`mls_rs::Client::create_group_with_id`] for details.
    pub async fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<Group, MlSrsError> {
        let extensions = mls_rs::ExtensionList::new();
        let inner = match group_id {
            Some(group_id) => {
                self.inner
                    .create_group_with_id(group_id, extensions)
                    .await?
            }
            None => self.inner.create_group(extensions).await?,
        };
        Ok(Group {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Join an existing group.
    ///
    /// You must supply `ratchet_tree` if the client that created
    /// `welcome_message` did not set `use_ratchet_tree_extension`.
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub async fn join_group(
        &self,
        ratchet_tree: Option<RatchetTree>,
        welcome_message: &Message,
    ) -> Result<JoinInfo, MlSrsError> {
        let ratchet_tree = ratchet_tree.map(TryInto::try_into).transpose()?;
        let (group, new_member_info) = self
            .inner
            .join_group(ratchet_tree, &welcome_message.inner)
            .await?;

        let group = Arc::new(Group {
            inner: Arc::new(Mutex::new(group)),
        });
        let group_info_extensions = Arc::new(new_member_info.group_info_extensions.into());
        Ok(JoinInfo {
            group,
            group_info_extensions,
        })
    }

    /// Load an existing group.
    ///
    /// See [`mls_rs::Client::load_group`] for details.
    pub async fn load_group(&self, group_id: Vec<u8>) -> Result<Group, MlSrsError> {
        self.inner
            .load_group(&group_id)
            .await
            .map(|g| Group {
                inner: Arc::new(Mutex::new(g)),
            })
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RatchetTree {
    pub bytes: Vec<u8>,
}

impl TryFrom<mls_rs::group::ExportedTree<'_>> for RatchetTree {
    type Error = MlSrsError;

    fn try_from(exported_tree: mls_rs::group::ExportedTree<'_>) -> Result<Self, MlSrsError> {
        let bytes = exported_tree.to_bytes()?;
        Ok(Self { bytes })
    }
}

impl TryFrom<RatchetTree> for group::ExportedTree<'static> {
    type Error = MlSrsError;

    fn try_from(ratchet_tree: RatchetTree) -> Result<Self, MlSrsError> {
        group::ExportedTree::from_bytes(&ratchet_tree.bytes).map_err(Into::into)
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CommitOutput {
    /// Commit message to send to other group members.
    pub commit_message: Arc<Message>,

    /// Welcome message to send to new group members. This will be
    /// `None` if the commit did not add new members.
    pub welcome_message: Option<Arc<Message>>,

    /// Ratchet tree that can be sent out of band if the ratchet tree
    /// extension is not used.
    pub ratchet_tree: Option<RatchetTree>,

    /// A group info that can be provided to new members in order to
    /// enable external commit functionality.
    pub group_info: Option<Arc<Message>>,
    
    /// Proposals that were received in the prior epoch but not included in the following commit.
    pub unused_proposals: Vec<Arc<Proposal>>,
}

impl TryFrom<mls_rs::group::CommitOutput> for CommitOutput {
    type Error = MlSrsError;

    fn try_from(commit_output: mls_rs::group::CommitOutput) -> Result<Self, MlSrsError> {
        let commit_message = Arc::new(commit_output.commit_message.into());
        let welcome_message = commit_output
            .welcome_messages
            .into_iter()
            .next()
            .map(|welcome_message| Arc::new(welcome_message.into()));
        let ratchet_tree = commit_output
            .ratchet_tree
            .map(TryInto::try_into)
            .transpose()?;
        let group_info = commit_output
            .external_commit_group_info
            .map(|group_info| Arc::new(group_info.into()));
        let unused_proposals = commit_output
            .unused_proposals
            .into_iter()
            .map(|proposal_info| Arc::new(proposal_info.proposal.into() ) )
            .collect();

        Ok(Self {
            commit_message,
            welcome_message,
            ratchet_tree,
            group_info,
            unused_proposals
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct SigningIdentity {
    inner: identity::SigningIdentity,
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
}

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
#[derive(Clone, uniffi::Object)]
pub struct Group {
    inner: Arc<Mutex<mls_rs::Group<UniFFIConfig>>>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl Group {
    #[cfg(not(mls_build_async))]
    fn inner(&self) -> std::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().unwrap()
    }

    #[cfg(mls_build_async)]
    async fn inner(&self) -> tokio::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().await
    }
}

/// Find the identity for the member with a given index.
fn index_to_identity(
    group: &mls_rs::Group<UniFFIConfig>,
    index: u32,
) -> Result<identity::SigningIdentity, MlSrsError> {
    let member = group
        .member_at_index(index)
        .ok_or(MlsError::InvalidNodeIndex(index))?;
    Ok(member.signing_identity)
}

/// Extract the basic credential identifier from a  from a key package.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
async fn signing_identity_to_identifier(
    signing_identity: &identity::SigningIdentity,
) -> Result<Vec<u8>, MlSrsError> {
    let identifier = basic::BasicIdentityProvider::new()
        .identity(signing_identity, &mls_rs::ExtensionList::new())
        .await
        .map_err(|err| err.into_any_error())?;
    Ok(identifier)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
impl Group {
    /// Write the current state of the group to storage defined by
    /// [`ClientConfig::group_state_storage`]
    pub async fn write_to_storage(&self) -> Result<(), MlSrsError> {
        let mut group = self.inner().await;
        group.write_to_storage().await.map_err(Into::into)
    }

    /// Export the current epoch's ratchet tree in serialized format.
    ///
    /// This function is used to provide the current group tree to new
    /// members when `use_ratchet_tree_extension` is set to false in
    /// `ClientConfig`.
    pub async fn export_tree(&self) -> Result<RatchetTree, MlSrsError> {
        let group = self.inner().await;
        group.export_tree().try_into()
    }

    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// Returns the resulting commit message. See
    /// [`mls_rs::Group::commit`] for details.
    pub async fn commit(&self) -> Result<CommitOutput, MlSrsError> {
        let mut group = self.inner().await;
        let commit_output = group.commit(Vec::new()).await?;
        commit_output.try_into()
    }

    /// Commit the addition of one or more members.
    ///
    /// The members are representated by key packages. The result is
    /// the welcome messages to send to the new members.
    ///
    /// See [`mls_rs::group::CommitBuilder::add_member`] for details.
    pub async fn add_members(
        &self,
        key_packages: Vec<Arc<Message>>,
    ) -> Result<CommitOutput, MlSrsError> {
        let mut group = self.inner().await;
        let mut commit_builder = group.commit_builder();
        for key_package in key_packages {
            commit_builder = commit_builder.add_member(arc_unwrap_or_clone(key_package).inner)?;
        }
        let commit_output = commit_builder.build().await?;
        commit_output.try_into()
    }

    /// Propose to add one or more members to this group.
    ///
    /// The members are representated by key packages. The result is
    /// the proposal messages to send to the group.
    ///
    /// See [`mls_rs::Group::propose_add`] for details.
    pub async fn propose_add_members(
        &self,
        key_packages: Vec<Arc<Message>>,
    ) -> Result<Vec<Arc<Message>>, MlSrsError> {
        let mut group = self.inner().await;

        let mut messages = Vec::with_capacity(key_packages.len());
        for key_package in key_packages {
            let key_package = arc_unwrap_or_clone(key_package);
            let message = group.propose_add(key_package.inner, Vec::new()).await?;
            messages.push(Arc::new(message.into()));
        }

        Ok(messages)
    }

    /// Propose and commit the removal of one or more members.
    ///
    /// The members are representated by their signing identities.
    ///
    /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    pub async fn remove_members(
        &self,
        signing_identities: &[Arc<SigningIdentity>],
    ) -> Result<CommitOutput, MlSrsError> {
        let mut group = self.inner().await;

        // Find member indices
        let mut member_indixes = Vec::with_capacity(signing_identities.len());
        for signing_identity in signing_identities {
            let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
            let member = group.member_with_identity(&identifier).await?;
            member_indixes.push(member.index);
        }

        let mut commit_builder = group.commit_builder();
        for index in member_indixes {
            commit_builder = commit_builder.remove_member(index)?;
        }
        let commit_output = commit_builder.build().await?;
        commit_output.try_into()
    }

    /// Propose to remove one or more members from this group.
    ///
    /// The members are representated by their signing identities. The
    /// result is the proposal messages to send to the group.
    ///
    /// See [`mls_rs::group::Group::propose_remove`] for details.
    pub async fn propose_remove_members(
        &self,
        signing_identities: &[Arc<SigningIdentity>],
    ) -> Result<Vec<Arc<Message>>, MlSrsError> {
        let mut group = self.inner().await;

        let mut messages = Vec::with_capacity(signing_identities.len());
        for signing_identity in signing_identities {
            let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
            let member = group.member_with_identity(&identifier).await?;
            let message = group.propose_remove(member.index, Vec::new()).await?;
            messages.push(Arc::new(message.into()));
        }

        Ok(messages)
    }

    /// Encrypt an application message using the current group state.
    ///
    /// An application message is an application-specific payload,
    /// e.g., an UTF-8 encoded text message in a chat app. The
    /// encoding is not determined by MLS and applications will have
    /// to implement their own mechanism for how to agree on the
    /// content encoding.
    ///
    /// The other group members will find the message in
    /// [`ReceivedMessage::ApplicationMessage`] after calling
    /// [`Group::process_incoming_message`].
    pub async fn encrypt_application_message(
        &self,
         message: &[u8],
         authenticated_data: Vec<u8>
        ) -> Result<Message, MlSrsError> {
        let mut group = self.inner().await;
        let mls_message = group
            .encrypt_application_message(message, authenticated_data)
            .await?;
        Ok(mls_message.into())
    }

    /// Process an inbound message for this group.
    pub async fn process_incoming_message(
        &self,
        message: Arc<Message>,
    ) -> Result<ReceivedMessage, MlSrsError> {
        let message = arc_unwrap_or_clone(message);
        let mut group = self.inner().await;
        match group.process_incoming_message(message.inner).await? {
            group::ReceivedMessage::ApplicationMessage(application_message) => {
                let sender =
                    Arc::new(index_to_identity(&group, application_message.sender_index)?.into());
                let data = application_message.data().to_vec();
                let authenticated_data = application_message.authenticated_data.to_vec();
                Ok(ReceivedMessage::ApplicationMessage { sender, data, authenticated_data })
            }
            group::ReceivedMessage::Commit(commit_message) => {
                let committer =
                    Arc::new(index_to_identity(&group, commit_message.committer)?.into());
                let roster_update = RosterUpdate::new(commit_message.state_update.roster_update());
                let authenticated_data = commit_message.authenticated_data.to_vec();
                Ok(ReceivedMessage::Commit {
                    committer,
                    roster_update,
                    authenticated_data
                })
            }
            group::ReceivedMessage::Proposal(proposal_message) => {
                let sender = match proposal_message.sender {
                    mls_rs::group::ProposalSender::Member(index) => {
                        Arc::new(index_to_identity(&group, index)?.into())
                    }
                    _ => todo!("External and NewMember proposal senders are not supported"),
                };
                let proposal = Arc::new(proposal_message.proposal.into());
                let authenticated_data = proposal_message.authenticated_data.to_vec();
                Ok(ReceivedMessage::ReceivedProposal { sender, proposal, authenticated_data })
            }
            // TODO: group::ReceivedMessage::GroupInfo does not have any
            // public methods (unless the "ffi" Cargo feature is set).
            // So perhaps we don't need it?
            group::ReceivedMessage::GroupInfo(_) => Ok(ReceivedMessage::GroupInfo),
            group::ReceivedMessage::Welcome => Ok(ReceivedMessage::Welcome),
            group::ReceivedMessage::KeyPackage(_) => Ok(ReceivedMessage::KeyPackage),
        }
    }

    //MARK: Germ helpers
     /// # Warning
    ///
    /// The indexes within this roster do not correlate with indexes of users
    /// within [`ReceivedMessage`] content descriptions due to the layout of
    /// member information within a MLS group state.
    pub async fn members(&self) -> Vec<MLSMember> {
        // let group = self.inner().await;
        self.inner().await
            .roster()
            .members()
            .iter()
            .map(|member| member.clone().into() )
            .collect()
    }

    pub async fn group_id(&self) -> Vec<u8> {
        self.inner().await.group_id().to_vec()
    }

    pub async fn current_epoch(&self) -> u64 {
        self.inner().await.current_epoch()
    }

    pub async fn current_member_index(&self) -> u32 {
        self.inner().await.current_member_index()
    }

    //for proposing in my own group
    pub async fn propose_update (
        &self,
        signer: Option<SignatureSecretKey>,
        signing_identity: Option<Arc<SigningIdentity>>,
        authenticated_data: Vec<u8>
    ) -> Result<Message, MlSrsError> {
        let mut group = self.inner().await;

        match (signer, signing_identity) {
            (Some(signer), Some(signing_identity)) => {
                let message = group.propose_update_with_identity(
                    signer.into(),
                    arc_unwrap_or_clone(signing_identity).inner,
                    authenticated_data
                );
                Ok(message?.into())
            },
            (None, None) => {
                Ok(group.propose_update(authenticated_data)?.into())
            },
            _ => Err(MlSrsError::InconsistentOptionalParameters)
        }
    }

    pub async fn clear_proposal_cache(&self) {
        self.inner().await.clear_proposal_cache()
    }

    pub async fn proposal_cache_is_empty(&self) -> bool {
        self.inner().await.proposal_cache_is_empty()
    }

    pub async fn member_at_index(&self, index: u32) -> Option<MLSMember> {
        self.inner().await.member_at_index(index)
            .map(|message| message.into())
    }

    //Propose replace from update
    pub async fn propose_replace_from_update(
        &self,
        to_replace: u32,
        proposal: Arc<Proposal>,
        authenticated_data: Vec<u8>
    ) -> Result<Arc<Message>, MlSrsError> {
        let message = self.inner().await.propose_replace_from_update_message(
            to_replace,
            arc_unwrap_or_clone(proposal)._inner,
            authenticated_data
        )?;
        Ok(Arc::new(message.into()))
    }

    pub async fn commit_selected_proposals(
        &self,
        proposals_archives: Vec<ReceivedUpdate>,
        signer: Option<SignatureSecretKey>,
        signing_identity: Option<Arc<SigningIdentity>>,
        authenticated_data: Vec<u8>
    ) -> Result<CommitOutput, MlSrsError> {
        let mut group = self.inner().await;

        let updates: Result<Vec<mls_rs::group::proposal::Proposal>, MlsError> = proposals_archives
            .iter().map( |received_update| {
                let update_proposal = mls_rs::group::proposal::UpdateProposal::mls_decode(
                    &mut received_update.encoded_update.as_slice()
                );
                if received_update.epoch == group.current_epoch() {
                    Ok(mls_rs::group::proposal::Proposal::Update(update_proposal?))
                } else {
                    return group.propose_replace_from_update(
                        received_update.leaf_index,
                        mls_rs::group::proposal::Proposal::Update(update_proposal?),
                    );
                }
            })
            .collect();

        let builder = group.commit_builder()
                .raw_proposals(updates?)
                .authenticated_data(authenticated_data);

        match (signer, signing_identity) {
            (Some(signer), Some(signing_identity)) => {
                builder
                    .set_new_signing_identity(
                        signer.into(),
                        arc_unwrap_or_clone(signing_identity).inner
                    )
                    .build().await?
                    .try_into()
            },
            (None, None) => {
                builder
                    .build().await?
                    .try_into()
            },
            _ => Err(MlSrsError::InconsistentOptionalParameters)
        } 
    }
}

#[uniffi::export]
//to let us staple a commit to a message from the next epoch, we tuck the commit into the message's authenticated data
pub fn extract_stapled_commit(
    message_data: Vec<u8>
) -> Result<Option<Arc<Message>>, MlSrsError> {
    Ok(mls_rs::MlsMessage::extract_stapled_commit(message_data)?
        .map(|message| Arc::new(message.into())))
}

#[uniffi::export]
pub fn extract_stapled_update_commit(
    message_data: Vec<u8>
) -> Result<Message, MlSrsError> {
    let message = mls_rs::MlsMessage::extract_stapled_update_commit(message_data)?;
    Ok(message.into())
}

#[cfg(test)]
mod tests {
    #[cfg(not(mls_build_async))]
    use super::*;
    #[cfg(not(mls_build_async))]
    use crate::config::group_state::{EpochRecord, GroupStateStorage};
    #[cfg(not(mls_build_async))]
    use std::collections::HashMap;

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_simple_scenario() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;
        let message = alice_group.encrypt_application_message(
            b"hello, bob",
            vec![]
        )?;
        let received_message = bob_group.process_incoming_message(Arc::new(message))?;

        alice_group.write_to_storage()?;

        let ReceivedMessage::ApplicationMessage { sender: _, data, authenticated_data: _ } = received_message else {
            panic!("Wrong message type: {received_message:?}");
        };
        assert_eq!(data, b"hello, bob");

        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_germ_scenario() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;

        let message = alice_group.encrypt_application_message(
            b"hello, bob",
            vec![]
        )?;
        let received_message = bob_group.process_incoming_message(Arc::new(message))?;

        alice_group.write_to_storage()?;

        let ReceivedMessage::ApplicationMessage { sender: _, data, authenticated_data: _ } = received_message else {
            panic!("Wrong message type: {received_message:?}");
        };
        assert_eq!(data, b"hello, bob");

        //adding on additional germ steps here 
        let update = bob_group.propose_update( None, None,vec![] )?;
        let _ = bob_group.process_incoming_message(update.clone().into())?;

        let commit_output = bob_group.commit()?;
        println!("commit_output unused {:?}", commit_output.unused_proposals.len());
        let _ = bob_group.process_incoming_message(commit_output.commit_message.clone());
        let next_message = bob_group.encrypt_application_message(
            b"hello, alice",
            commit_output.commit_message.to_bytes()?
        )?;

        let extracted_commit_maybe = extract_stapled_commit(next_message.to_bytes()?)?;
        let Some(extracted_commit) = extracted_commit_maybe else {
            panic!("Missing stapled commit")
        };

        let _ = alice_group.process_incoming_message(extracted_commit);
        let received = alice_group.process_incoming_message(Arc::new(next_message))?;

        let ReceivedMessage::ApplicationMessage { sender: _, data: next_data, authenticated_data: _ } = received else {
            panic!("Wrong message type: {received:?}");
        };

        assert_eq!(next_data, b"hello, alice");

        //test multiple updates
        let first_update = alice_group.propose_update( None, None,vec![] )?;
        let second_update = alice_group.propose_update( None, None,vec![] )?;

        let extracted = extract_stapled_commit(first_update.to_bytes()?)?;
        assert!(extracted.is_none());

        let _ = bob_group.process_incoming_message(first_update.into())?;
        assert!(!bob_group.proposal_cache_is_empty());
        bob_group.clear_proposal_cache();
        assert!(bob_group.proposal_cache_is_empty());
        // let _ = bob_group.process_incoming_message(second_update.into())?;

        let commit_output = bob_group.commit()?;
        println!("commit_output unused {:?}", commit_output.unused_proposals.len());
        let _ = bob_group.process_incoming_message(commit_output.commit_message.clone())?;

        let result = alice_group.process_incoming_message(commit_output.commit_message)?;
        
        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_stapled_commit() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;

        //empty commit
        let commit_output = alice_group.commit()?;
        let _ = alice_group.process_incoming_message(commit_output.clone().commit_message)?;
        let update = alice_group.propose_update(
            None,
            None,
            commit_output.commit_message.to_bytes()?
        )?;
        alice_group.clear_proposal_cache();
        let message = alice_group.encrypt_application_message(
             b"hello, bob",
             update.inner.to_bytes()?
        )?;

        let _ = extract_stapled_update_commit(message.to_bytes()?);

        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_update_reflect() -> Result<(), MlSrsError> {
        let (alice_group, bob_group) = setup_test()?;

        let alice_update = alice_group.propose_update( None, None,vec![] )?;
        alice_group.clear_proposal_cache();

        let received_message = bob_group.process_incoming_message(Arc::new(alice_update))?;
        let ReceivedMessage::ReceivedProposal{
            sender, 
            proposal,
            authenticated_data
        } = received_message.clone().into() else {
            panic!("Wrong message type: {received_message:?}")
        };

        // let reflected = bob_group.reflect_update(
        //     0,
        //     proposal,
        //     vec![]
        // )?;

        // let _ = alice_group.process_incoming_message(reflected);
        // let commit = alice_group.commit()?;
        // alice_group.process_incoming_message(commit.commit_message);

        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_ratchet_tree_not_included() -> Result<(), MlSrsError> {
        let alice_config = ClientConfig {
            use_ratchet_tree_extension: true,
            ..ClientConfig::default()
        };

        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
        let group = alice.create_group(None)?;

        assert_eq!(group.commit()?.ratchet_tree, None);
        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_ratchet_tree_included() -> Result<(), MlSrsError> {
        let alice_config = ClientConfig {
            use_ratchet_tree_extension: false,
            ..ClientConfig::default()
        };

        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
        let group = alice.create_group(None)?;

        let ratchet_tree: group::ExportedTree =
            group.commit()?.ratchet_tree.unwrap().try_into().unwrap();
        group.inner().apply_pending_commit()?;

        assert_eq!(ratchet_tree, group.inner().export_tree());
        Ok(())
    }

    fn setup_test() -> Result<(Group, Group), MlSrsError> {
        let alice_config = ClientConfig {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);

        let bob_config = ClientConfig {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let bob_keypair = generate_signature_keypair(CipherSuite::Curve25519ChaCha)?;
        let bob = Client::new(b"bob".to_vec(), bob_keypair, bob_config);

        let alice_group = alice.create_group(None)?;
        let bob_key_package = bob.generate_key_package_message()?;
        let commit = alice_group.add_members(vec![Arc::new(bob_key_package)])?;
        alice_group.process_incoming_message(commit.commit_message)?;

        let bob_group = bob
            .join_group(None, &commit.welcome_message.unwrap())?
            .group;
        Ok((
            alice_group,
            arc_unwrap_or_clone(bob_group) 
        ))
    }

    #[derive(Debug, Default)]
    struct GroupStateData {
        state: Vec<u8>,
        epoch_data: Vec<EpochRecord>,
    }

    #[derive(Debug)]
    struct CustomGroupStateStorage {
        groups: Mutex<HashMap<Vec<u8>, GroupStateData>>,
    }

    impl CustomGroupStateStorage {
        fn new() -> Self {
            Self {
                groups: Mutex::new(HashMap::new()),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, GroupStateData>> {
            self.groups.lock().unwrap()
        }
    }

    impl GroupStateStorage for CustomGroupStateStorage {
        fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, MlSrsError> {
            let groups = self.lock();
            Ok(groups.get(&group_id).map(|group| group.state.clone()))
        }

        fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, MlSrsError> {
            let groups = self.lock();
            match groups.get(&group_id) {
                Some(group) => {
                    let epoch_record =
                    group.epoch_data.iter().find(|record| record.id == epoch_id);
                    let data = epoch_record.map(|record| record.data.clone());
                    Ok(data)
                }
                None => Ok(None),
            }
        }

        fn write(
            &self,
            group_id: Vec<u8>,
            group_state: Vec<u8>,
            epoch_inserts: Vec<EpochRecord>,
            epoch_updates: Vec<EpochRecord>,
            ) -> Result<(), MlSrsError> {
            let mut groups = self.lock();

            let group = groups.entry(group_id).or_default();
            group.state = group_state;
            for insert in epoch_inserts {
                group.epoch_data.push(insert);
            }

            for update in epoch_updates {
                for epoch in group.epoch_data.iter_mut() {
                    if epoch.id == update.id {
                        epoch.data = update.data;
                        break;
                    }
                }
            }

            Ok(())
        }

        fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, MlSrsError> {
            let groups = self.lock();
            Ok(groups
                .get(&group_id)
                .and_then(|GroupStateData { epoch_data, .. }| epoch_data.last())
                .map(|last| last.id))
        }
    }
}
