use std::fmt::Debug;
use std::sync::Arc;

use mls_rs::{
    client_builder::{self, WithKeyPackageRepo, WithGroupStateStorage},
    identity::basic,
    storage_provider::in_memory::InMemoryKeyPackageStorage,
    storage_provider::in_memory::InMemoryGroupStateStorage
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
    basic::BasicIdentityProvider,
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
