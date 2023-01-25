use crate::{cipher_suite::CipherSuite, identity::SigningIdentity};
use indexmap::IndexMap;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use super::crypto::SignatureSecretKey;

pub trait KeychainStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error>;

    fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, SignatureSecretKey)>, Self::Error>;

    fn signer(&self, identity: &SigningIdentity)
        -> Result<Option<SignatureSecretKey>, Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychain {
    secret_keys: Arc<Mutex<IndexMap<SigningIdentity, (CipherSuite, SignatureSecretKey)>>>,
}

impl InMemoryKeychain {
    pub fn new() -> InMemoryKeychain {
        InMemoryKeychain {
            secret_keys: Default::default(),
        }
    }

    pub fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) {
        self.secret_keys
            .lock()
            .unwrap()
            .insert(identity, (cipher_suite, signer));
    }

    pub fn signer(&self, identity: &SigningIdentity) -> Option<SignatureSecretKey> {
        self.secret_keys
            .lock()
            .unwrap()
            .get(identity)
            .map(|v| v.1.clone())
    }

    pub fn delete(&mut self, identity: &SigningIdentity) {
        self.secret_keys.lock().unwrap().remove(identity);
    }

    fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Vec<(SigningIdentity, SignatureSecretKey)> {
        let all_keys = self.secret_keys.lock().unwrap();

        all_keys
            .iter()
            .filter_map(|(signing_id, (cs, key))| {
                if cs == &cipher_suite {
                    Some((signing_id.clone(), key.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    #[cfg(any(test, feature = "benchmark"))]
    pub fn export(&self) -> Vec<(SigningIdentity, SignatureSecretKey)> {
        let map = self.secret_keys.lock().unwrap();
        map.iter().map(|(k, v)| (k.clone(), v.1.clone())).collect()
    }
}

impl KeychainStorage for InMemoryKeychain {
    type Error = Infallible;

    fn signer(
        &self,
        identity: &SigningIdentity,
    ) -> Result<Option<SignatureSecretKey>, Self::Error> {
        Ok(self.signer(identity))
    }

    fn insert(
        &mut self,
        identity: SigningIdentity,
        signer: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        self.insert(identity, signer, cipher_suite);
        Ok(())
    }

    fn delete(&mut self, identity: &SigningIdentity) -> Result<(), Self::Error> {
        self.delete(identity);
        Ok(())
    }

    fn get_identities(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<(SigningIdentity, SignatureSecretKey)>, Self::Error> {
        Ok(self.get_identities(cipher_suite))
    }
}