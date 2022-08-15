use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::ops::Deref;

use ferriscrypt::asym::ec_key::EcKeyError;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::HpkeError;

use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use math as tree_math;
use math::TreeMathError;
use node::{LeafIndex, NodeIndex, NodeVec, NodeVecError};

use self::leaf_node::{LeafNode, LeafNodeError};
use self::tree_utils::build_ascii_tree;

use crate::cipher_suite::CipherSuite;
use crate::extension::ExtensionError;
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{KeyPackageError, KeyPackageGenerationError, KeyPackageValidationError};
use crate::tree_kem::parent_hash::ParentHashError;
use crate::tree_kem::path_secret::PathSecretError;
use crate::tree_kem::tree_hash::TreeHashes;

pub use tree_index::TreeIndexError;

mod capabilities;
mod lifetime;
pub(crate) mod math;
pub mod node;
pub mod parent_hash;
pub mod path_secret;
mod private;
mod tree_hash;
pub mod tree_validator;
pub mod update_path;

pub use capabilities::*;
pub use lifetime::*;
pub use private::*;
pub use update_path::*;

use tree_index::*;

use self::path_secret::{PathSecret, PathSecretGenerator};
pub mod kem;
pub mod leaf_node;
pub mod leaf_node_validator;
mod tree_index;
pub(crate) mod tree_utils;

#[derive(Error, Debug)]
pub enum RatchetTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    KeyPackageGeneratorError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    ParentHashError(#[from] ParentHashError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    PathSecretError(#[from] PathSecretError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    TreeIndexError(#[from] TreeIndexError),
    #[error("invalid update path signature")]
    InvalidUpdatePathSignature,
    // TODO: This should probably tell you the expected key vs actual key
    #[error("update path pub key mismatch")]
    PubKeyMismatch,
    #[error("invalid leaf signature")]
    InvalidLeafSignature,
    #[error("tree hash mismatch")]
    TreeHashMismatch,
    #[error("bad update: no suitable secret key")]
    UpdateErrorNoSecretKey,
    #[error("invalid lca, not found on direct path")]
    LcaNotFoundInDirectPath,
    #[error("bad state: missing own credential")]
    MissingSelfCredential,
    #[error("update path missing parent hash")]
    ParentHashNotFound,
    #[error("update path parent hash mismatch")]
    ParentHashMismatch,
    #[error("invalid parent hash: {0}")]
    InvalidParentHash(String),
    #[error("HPKE decrypt called with incorrect secret key, ciphertext or context")]
    HPKEDecryptionError,
    #[error("decrypting commit from self")]
    DecryptFromSelf,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TreeKemPublic {
    pub cipher_suite: CipherSuite,
    index: TreeIndex,
    pub(crate) nodes: NodeVec,
    tree_hashes: TreeHashes,
}

impl PartialEq for TreeKemPublic {
    fn eq(&self, other: &Self) -> bool {
        self.cipher_suite == other.cipher_suite
            && self.index == other.index
            && self.nodes == other.nodes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct SecretPath {
    #[tls_codec(with = "crate::tls::DefMap")]
    path_secrets: HashMap<NodeIndex, PathSecret>,
    root_secret: PathSecret,
}

impl SecretPath {
    pub fn get_path_secret(&self, index: NodeIndex) -> Option<PathSecret> {
        self.path_secrets.get(&index).cloned()
    }
}

impl TreeKemPublic {
    pub fn new(cipher_suite: CipherSuite) -> TreeKemPublic {
        TreeKemPublic {
            cipher_suite,
            index: Default::default(),
            nodes: Default::default(),
            tree_hashes: Default::default(),
        }
    }

    pub(crate) fn import_node_data(
        cipher_suite: CipherSuite,
        nodes: NodeVec,
    ) -> Result<TreeKemPublic, RatchetTreeError> {
        let index = nodes.non_empty_leaves().try_fold(
            TreeIndex::new(),
            |mut tree_index, (leaf_index, leaf)| {
                tree_index.insert(leaf_index, leaf)?;
                Ok::<_, RatchetTreeError>(tree_index)
            },
        )?;

        let tree = TreeKemPublic {
            cipher_suite,
            index,
            nodes,
            tree_hashes: Default::default(),
        };

        Ok(tree)
    }

    pub(crate) fn export_node_data(&self) -> NodeVec {
        self.nodes.clone()
    }

    pub fn derive(
        cipher_suite: CipherSuite,
        leaf_node: LeafNode,
        secret_key: HpkeSecretKey,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError> {
        let mut public_tree = TreeKemPublic::new(cipher_suite);
        public_tree.add_leaves(vec![leaf_node])?;

        let private_tree = TreeKemPrivate::new_self_leaf(LeafIndex(0), secret_key);

        Ok((public_tree, private_tree))
    }

    pub fn total_leaf_count(&self) -> u32 {
        self.nodes.total_leaf_count()
    }

    pub fn occupied_leaf_count(&self) -> u32 {
        self.nodes.occupied_leaf_count()
    }

    pub fn get_leaf_node(&self, index: LeafIndex) -> Result<&LeafNode, RatchetTreeError> {
        self.nodes.borrow_as_leaf(index).map_err(|e| e.into())
    }

    pub fn find_leaf_node(&self, leaf_node: &LeafNode) -> Option<LeafIndex> {
        self.nodes.non_empty_leaves().find_map(|(index, node)| {
            if node.deref() == leaf_node {
                Some(index)
            } else {
                None
            }
        })
    }

    // Note that a partial failure of this function will leave the tree in a bad state. Modifying a
    // tree should always be done on a clone of the tree, which is how commits are processed
    pub fn add_leaves(
        &mut self,
        leaf_nodes: Vec<LeafNode>,
    ) -> Result<Vec<LeafIndex>, RatchetTreeError> {
        #[derive(Default)]
        struct Accumulator {
            new_leaf_indexes: Vec<LeafIndex>,
        }

        impl AccumulateBatchResults for Accumulator {
            type Output = Vec<LeafIndex>;

            fn on_add(
                &mut self,
                _: usize,
                r: Result<LeafIndex, RatchetTreeError>,
            ) -> Result<(), RatchetTreeError> {
                self.new_leaf_indexes.push(r?);
                Ok(())
            }

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(self.new_leaf_indexes)
            }
        }

        self.batch_edit(Accumulator::default(), &[], &[], &leaf_nodes)
    }

    pub fn remove_leaves(
        &mut self,
        indexes: Vec<LeafIndex>,
    ) -> Result<Vec<(LeafIndex, LeafNode)>, RatchetTreeError> {
        #[derive(Default)]
        struct Accumulator {
            removed: Vec<(LeafIndex, LeafNode)>,
        }

        impl AccumulateBatchResults for Accumulator {
            type Output = Vec<(LeafIndex, LeafNode)>;

            fn on_remove(
                &mut self,
                _: usize,
                r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
            ) -> Result<(), RatchetTreeError> {
                self.removed.push(r?);
                Ok(())
            }

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(self.removed)
            }
        }

        self.batch_edit(Accumulator::default(), &[], &indexes, &[])
    }

    pub fn rekey_leaf(
        &mut self,
        index: LeafIndex,
        leaf_node: LeafNode,
    ) -> Result<(), RatchetTreeError> {
        // Update the leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(index)?;

        // Update the cache
        self.index.remove(existing_leaf);
        self.index.insert(index, &leaf_node)?;

        *existing_leaf = leaf_node;

        Ok(())
    }

    pub fn update_leaf(
        &mut self,
        index: LeafIndex,
        leaf_node: LeafNode,
    ) -> Result<(), RatchetTreeError> {
        struct Accumulator;

        impl AccumulateBatchResults for Accumulator {
            type Output = ();

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(())
            }
        }

        self.batch_edit(Accumulator, &[(index, leaf_node)], &[], &[])
    }

    pub fn get_leaf_nodes(&self) -> Vec<&LeafNode> {
        self.nodes.non_empty_leaves().map(|(_, l)| l).collect()
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item = (LeafIndex, &LeafNode)> + '_ {
        self.nodes.non_empty_leaves()
    }

    fn update_node(
        &mut self,
        pub_key: HpkePublicKey,
        index: NodeIndex,
    ) -> Result<(), RatchetTreeError> {
        self.nodes
            .borrow_or_fill_node_as_parent(index, &pub_key)
            .map_err(|e| e.into())
            .map(|p| {
                p.public_key = pub_key;
                p.unmerged_leaves = vec![];
            })
    }

    pub fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &ValidatedUpdatePath,
    ) -> Result<Vec<(u32, u32)>, RatchetTreeError> {
        // Install the new leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(sender)?;
        let original_leaf_node = existing_leaf.clone();

        *existing_leaf = update_path.leaf_node.clone();

        // Update the rest of the nodes on the direct path
        let updated_pks = update_path
            .nodes
            .iter()
            .map(|update| &update.public_key)
            .collect::<Vec<_>>();

        let filtered_direct_path_co_path = self.nodes.filtered_direct_path_co_path(sender)?;

        self.apply_parent_node_updates(updated_pks, &filtered_direct_path_co_path)?;

        self.index.remove(&original_leaf_node);
        self.index.insert(sender, &update_path.leaf_node)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(update_path))?;

        Ok(filtered_direct_path_co_path)
    }

    fn apply_parent_node_updates(
        &mut self,
        updated_pks: Vec<&HpkePublicKey>,
        filtered_direct_path_co_path: &[(u32, u32)],
    ) -> Result<(), RatchetTreeError> {
        updated_pks
            .into_iter()
            .zip(filtered_direct_path_co_path)
            .try_for_each(|(pub_key, (node_index, _))| {
                self.update_node(pub_key.clone(), *node_index)
            })
    }

    pub fn direct_path_keys(
        &self,
        index: LeafIndex,
    ) -> Result<Vec<Option<HpkePublicKey>>, RatchetTreeError> {
        let indexes = self.nodes.direct_path(index)?;

        indexes
            .iter()
            .map(|&i| {
                Ok(self
                    .nodes
                    .borrow_node(i)?
                    .as_ref()
                    .map(|n| n.public_key())
                    .cloned())
            })
            .collect::<Result<Vec<_>, RatchetTreeError>>()
    }

    fn update_unmerged(&mut self, index: LeafIndex) -> Result<(), RatchetTreeError> {
        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?.into_iter().for_each(|i| {
            if let Ok(p) = self.nodes.borrow_as_parent_mut(i) {
                p.unmerged_leaves.push(index)
            }
        });

        Ok(())
    }

    pub fn batch_edit<A>(
        &mut self,
        mut accumulator: A,
        updates: &[(LeafIndex, LeafNode)],
        removals: &[LeafIndex],
        additions: &[LeafNode],
    ) -> Result<A::Output, RatchetTreeError>
    where
        A: AccumulateBatchResults,
    {
        let mut updates = updates
            .iter()
            .map(|(i, l)| (*i, l))
            .map(Some)
            .collect::<Vec<_>>();

        let mut removals = removals.iter().copied().map(Some).collect::<Vec<_>>();
        let tree_index = std::mem::take(&mut self.index);
        let mut removed_indexes = HashSet::<LeafIndex>::new();

        // Remove about-to-be-removed leaves from tree index.
        let new_tree_index =
            removals
                .iter_mut()
                .enumerate()
                .try_fold(tree_index, |mut tree_index, (i, op)| {
                    let r = empty_on_fail(op, |&leaf_index| {
                        removed_indexes
                            .insert(leaf_index)
                            .then_some(())
                            .ok_or(NodeVecError::NotLeafNode)?;
                        let leaf = self.nodes.borrow_as_leaf(leaf_index)?;
                        tree_index.remove(leaf);
                        Ok(())
                    });

                    r.or_else(|e| accumulator.on_remove(i, Err(e)))
                        .map(|_| tree_index)
                })?;

        // Verify updates have valid indexes.
        updates.iter_mut().enumerate().try_for_each(|(i, op)| {
            let r = empty_on_fail(op, |&(leaf_index, _)| {
                let _ = self.nodes.borrow_as_leaf(leaf_index)?;
                Ok(())
            });

            r.or_else(|e| accumulator.on_update(i, Err(e)))
        })?;

        // Ignore updates for indexes that are removed. Such a commit is invalid as per the RFC.
        updates.iter_mut().for_each(|op| {
            if op.as_ref().map_or(false, |(leaf_index, _)| {
                removed_indexes.contains(leaf_index)
            }) {
                *op = None;
            }
        });

        let mut tree_index = loop {
            let tree_index = new_tree_index.clone();

            // Remove about-to-be-updated leaves from tree index.
            //
            // This is done to ensure that inter-dependent updates will not be rejected, e.g.
            // when an update U1 updates `pk1` to `pk2` and another update U2 updates `pk2` to `pk3`.
            // Applying U1 fails unless U2 is applied first or `pk2` is removed. The latter approach
            // is implemented here.
            let tree_index = updates
                .iter()
                .copied()
                .flatten()
                .map(|(leaf_index, _)| leaf_index)
                .fold(tree_index, |mut tree_index, leaf_index| {
                    if let Ok(leaf) = self.nodes.borrow_as_leaf(leaf_index) {
                        tree_index.remove(leaf);
                    }
                    tree_index
                });

            // Add updates to tree index.
            let tree_index =
                updates
                    .iter_mut()
                    .enumerate()
                    .try_fold(tree_index, |mut tree_index, (i, op)| {
                        let mut update_failed = false;

                        let r = empty_on_fail(op, |&(leaf_index, leaf)| {
                            match tree_index.insert(leaf_index, leaf) {
                                Ok(_) => Ok(()),
                                Err(e) => {
                                    update_failed = true;
                                    Err(e.into())
                                }
                            }
                        });

                        r.or_else(|e| accumulator.on_update(i, Err(e)))
                            .map_err(Some)?;

                        if update_failed {
                            Err(None::<RatchetTreeError>)
                        } else {
                            Ok(tree_index)
                        }
                    });

            match tree_index {
                Ok(tree_index) => break Ok(tree_index),
                Err(Some(e)) => break Err(e),
                Err(None) => {
                    // An update could not be applied, so its removal from the tree index needs to
                    // be reverted. However it may not be possible to revert it because another
                    // update might have introduced the same key in the index. To solve this,
                    // the failed update is removed from the list of updates to apply, the tree
                    // index is reverted to its state from before any update and updates are
                    // processed from the beginning.
                }
            }
        }?;

        updates
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, leaf)| leaf.map(|(li, l)| (i, li, l)))
            .try_for_each(|(i, leaf_index, leaf)| {
                *self
                    .nodes
                    .borrow_as_leaf_mut(leaf_index)
                    .expect("Index points to a leaf") = leaf.clone();

                self.nodes
                    .blank_direct_path(leaf_index)
                    .expect("Index points to a leaf");

                accumulator.on_update(i, Ok(leaf_index))
            })?;

        removals
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, leaf_index)| Some((i, leaf_index?)))
            .try_for_each(|(i, leaf_index)| {
                let leaf = self
                    .nodes
                    .blank_leaf_node(leaf_index)
                    .expect("Index is valid")
                    .expect("Index points to a leaf");

                self.nodes
                    .blank_direct_path(leaf_index)
                    .expect("Index points to a leaf");

                accumulator.on_remove(i, Ok((leaf_index, leaf)))
            })?;

        let (new_leaf_indexes, _) = additions.iter().enumerate().try_fold(
            (Vec::new(), LeafIndex(0)),
            |(mut leaf_indexes, start), (i, leaf)| {
                let leaf_index = self.nodes.insert_leaf(start, leaf.clone());

                let r = tree_index
                    .insert(leaf_index, leaf)
                    .map(|_| leaf_index)
                    .map_err(Into::into);

                let failed = r.is_err();
                accumulator.on_add(i, r)?;

                if failed {
                    // Revert insertion in the tree.
                    self.nodes
                        .blank_leaf_node(leaf_index)
                        .expect("Index points to a leaf");
                } else {
                    leaf_indexes.push(leaf_index);
                }

                Ok::<_, RatchetTreeError>((leaf_indexes, leaf_index))
            },
        )?;

        self.nodes.trim();

        new_leaf_indexes.iter().copied().for_each(|leaf_index| {
            self.update_unmerged(leaf_index)
                .expect("Index points to a leaf");
        });

        self.index = tree_index;

        let mut path_blanked = removals
            .iter()
            .copied()
            .flatten()
            .chain(
                updates
                    .iter()
                    .copied()
                    .flatten()
                    .map(|(leaf_index, _)| leaf_index),
            )
            .collect();

        self.update_hashes(&mut path_blanked, &new_leaf_indexes)
            .expect("All indexes are valid");
        accumulator.finish()
    }
}

fn empty_on_fail<T, F>(opt: &mut Option<T>, f: F) -> Result<(), RatchetTreeError>
where
    F: FnOnce(&T) -> Result<(), RatchetTreeError>,
{
    match &*opt {
        Some(x) => match f(x) {
            Ok(()) => Ok(()),
            Err(e) => {
                *opt = None;
                Err(e)
            }
        },
        None => Ok(()),
    }
}

impl Display for TreeKemPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", build_ascii_tree(&self.nodes))
    }
}

pub trait AccumulateBatchResults {
    type Output;

    fn on_update(
        &mut self,
        _: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn on_remove(
        &mut self,
        _: usize,
        r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn on_add(
        &mut self,
        _: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn finish(self) -> Result<Self::Output, RatchetTreeError>;
}

#[cfg(test)]
impl TreeKemPublic {
    pub fn do_update_node(
        &mut self,
        pub_key: HpkePublicKey,
        index: NodeIndex,
    ) -> Result<(), RatchetTreeError> {
        self.update_node(pub_key, index)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::{asym::ec_key::SecretKey, hpke::kem::HpkeSecretKey};

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key;

    use super::{
        leaf_node::{test_utils::get_basic_test_node, LeafNode},
        TreeKemPrivate, TreeKemPublic,
    };
    use crate::cipher_suite::CipherSuite;

    #[derive(Debug)]
    pub struct TestTree {
        pub public: TreeKemPublic,
        pub private: TreeKemPrivate,
        pub creator_leaf: LeafNode,
        pub creator_signing_key: SecretKey,
        pub creator_hpke_secret: HpkeSecretKey,
    }

    pub fn get_test_tree(cipher_suite: CipherSuite) -> TestTree {
        let (creator_leaf, creator_hpke_secret, creator_signing_key) =
            get_basic_test_node_sig_key(cipher_suite, "creator");

        let (test_public, test_private) = TreeKemPublic::derive(
            cipher_suite,
            creator_leaf.clone(),
            creator_hpke_secret.clone(),
        )
        .unwrap();

        TestTree {
            public: test_public,
            private: test_private,
            creator_leaf,
            creator_signing_key,
            creator_hpke_secret,
        }
    }

    pub fn get_test_leaf_nodes(cipher_suite: CipherSuite) -> Vec<LeafNode> {
        [
            get_basic_test_node(cipher_suite, "A"),
            get_basic_test_node(cipher_suite, "B"),
            get_basic_test_node(cipher_suite, "C"),
        ]
        .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher_suite::CipherSuite;

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNode;
    use crate::tree_kem::node::{
        LeafIndex, Node, NodeIndex, NodeTypeResolver, NodeVecError, Parent,
    };
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::test_utils::{get_test_leaf_nodes, get_test_tree};
    use crate::tree_kem::tree_index::TreeIndexError;
    use crate::tree_kem::{AccumulateBatchResults, RatchetTreeError, TreeKemPublic};
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    pub fn test_derive() {
        for cipher_suite in CipherSuite::all() {
            let test_tree = get_test_tree(cipher_suite);

            assert_eq!(
                test_tree.public.nodes[0],
                Some(Node::Leaf(test_tree.creator_leaf.clone()))
            );

            assert_eq!(test_tree.private.self_index, LeafIndex(0));

            assert_eq!(
                test_tree.private.secret_keys[&0],
                test_tree.creator_hpke_secret
            );
        }
    }

    #[test]
    fn test_import_export() {
        let cipher_suite = CipherSuite::P256Aes128;
        let mut test_tree = get_test_tree(cipher_suite);

        let additional_key_packages = get_test_leaf_nodes(cipher_suite);

        test_tree
            .public
            .add_leaves(additional_key_packages)
            .unwrap();

        let exported = test_tree.public.export_node_data();
        let imported = TreeKemPublic::import_node_data(cipher_suite, exported).unwrap();

        assert_eq!(test_tree.public.nodes, imported.nodes);
        assert_eq!(test_tree.public.index, imported.index);
    }

    #[test]
    fn test_add_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        let res = tree.add_leaves(leaf_nodes.clone()).unwrap();

        // The leaf count should be equal to the number of packages we added
        assert_eq!(res.len(), leaf_nodes.len());
        assert_eq!(tree.occupied_leaf_count(), leaf_nodes.len() as u32);

        // Each added package should be at the proper index and searchable in the tree
        res.into_iter().zip(leaf_nodes.clone()).for_each(|(r, kp)| {
            assert_eq!(tree.get_leaf_node(r).unwrap(), &kp);
        });

        // Verify the underlying state
        assert_eq!(tree.index.len(), tree.occupied_leaf_count() as usize);
        assert_eq!(tree.nodes.len(), 5);
        assert_eq!(tree.nodes[0], leaf_nodes[0].clone().into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], leaf_nodes[1].clone().into());
        assert_eq!(tree.nodes[3], None);
        assert_eq!(tree.nodes[4], leaf_nodes[2].clone().into());
    }

    #[test]
    fn test_get_key_packages() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let key_packages = tree.get_leaf_nodes();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    fn test_add_leaf_duplicate() {
        let cipher_suite = CipherSuite::P256Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let add_res = tree.add_leaves(key_packages);

        assert_matches!(
            add_res,
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateSignatureKeys(LeafIndex(0))
            ))
        );
    }

    #[test]
    fn test_add_leaf_empty_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);

        tree.add_leaves([key_packages[0].clone()].to_vec()).unwrap();
        tree.nodes[0] = None; // Set the original first node to none
        tree.add_leaves([key_packages[1].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[0], key_packages[1].clone().into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], key_packages[0].clone().into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    fn test_add_leaf_unmerged() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);

        tree.add_leaves([key_packages[0].clone(), key_packages[1].clone()].to_vec())
            .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_leaves([key_packages[2].clone()].to_vec()).unwrap();

        assert_eq!(
            tree.nodes[3].as_parent().unwrap().unmerged_leaves,
            vec![LeafIndex(3)]
        )
    }

    #[test]
    fn test_update_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        // Add in parent nodes so we can detect them clearing after update
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                tree.nodes
                    .borrow_or_fill_node_as_parent(i, &b"pub_key".to_vec().into())
                    .unwrap();
            });

        let original_size = tree.occupied_leaf_count();
        let original_leaf_index = LeafIndex(1);

        let updated_leaf = get_basic_test_node(cipher_suite, "newpk");

        tree.update_leaf(original_leaf_index, updated_leaf.clone())
            .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.occupied_leaf_count(), original_size);

        // The cache of tree package indexes should not have grown
        assert_eq!(tree.index.len() as u32, tree.occupied_leaf_count());

        // The key package should be updated in the tree
        assert_eq!(
            tree.get_leaf_node(original_leaf_index).unwrap(),
            &updated_leaf
        );

        // Verify that the direct path has been cleared
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                assert!(tree.nodes[i as usize].is_none());
            });
    }

    #[test]
    fn test_update_leaf_not_found() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let new_key_package = get_basic_test_node(cipher_suite, "new");

        assert_matches!(
            tree.update_leaf(LeafIndex(128), new_key_package),
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    fn test_remove_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        let indexes = tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        // Remove two leaves from the tree
        let expected_result: Vec<(LeafIndex, LeafNode)> = indexes
            .clone()
            .into_iter()
            .zip(key_packages)
            .map(|(index, ln)| (index, ln))
            .collect();

        let res = tree.remove_leaves(indexes.clone()).unwrap();

        assert_eq!(res, expected_result);

        // The leaves should be removed from the tree
        assert_eq!(
            tree.occupied_leaf_count(),
            original_leaf_count - indexes.len() as u32
        );
    }

    #[test]
    fn test_remove_leaf_middle() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        let to_remove = tree.add_leaves(leaf_nodes.clone()).unwrap()[0];
        let original_leaf_count = tree.occupied_leaf_count();

        let res = tree.remove_leaves(vec![to_remove]).unwrap();

        assert_eq!(res, vec![(to_remove, leaf_nodes[0].clone())]);

        // The leaf count should have been reduced by 1
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 1);

        // There should be a blank in the tree
        assert_eq!(
            tree.nodes.get(NodeIndex::from(to_remove) as usize).unwrap(),
            &None
        );
    }

    #[test]
    fn test_create_blanks() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let to_remove = vec![LeafIndex(2)];

        // Remove the leaf from the tree
        tree.remove_leaves(to_remove).unwrap();

        // The occupied leaf count should have been reduced by 1
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 1);

        // The total leaf count should remain unchanged
        assert_eq!(tree.total_leaf_count(), original_leaf_count);

        // The location of key_packages[1] should now be blank
        let removed_location = tree
            .nodes
            .get(NodeIndex::from(LeafIndex(2)) as usize)
            .unwrap();

        assert_eq!(removed_location, &None);
    }

    #[test]
    fn test_remove_leaf_failure() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        assert_matches!(
            tree.remove_leaves(vec![LeafIndex(128)]),
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    fn test_find_leaf_node() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(leaf_nodes.clone()).unwrap();

        // Find each node
        for (i, leaf_node) in leaf_nodes.iter().enumerate() {
            let expected_index = LeafIndex(i as u32 + 1);
            assert_eq!(tree.find_leaf_node(leaf_node), Some(expected_index));
        }
    }

    #[derive(Debug, Default)]
    struct BatchAccumulator {
        additions: Vec<LeafIndex>,
        removals: Vec<(LeafIndex, LeafNode)>,
        updates: Vec<LeafIndex>,
    }

    impl AccumulateBatchResults for BatchAccumulator {
        type Output = Self;

        fn on_add(
            &mut self,
            _: usize,
            r: Result<LeafIndex, RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.additions.push(r?);
            Ok(())
        }

        fn on_remove(
            &mut self,
            _: usize,
            r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.removals.push(r?);
            Ok(())
        }

        fn on_update(
            &mut self,
            _: usize,
            r: Result<LeafIndex, RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.updates.push(r?);
            Ok(())
        }

        fn finish(self) -> Result<Self::Output, RatchetTreeError> {
            Ok(self)
        }
    }

    #[test]
    fn batch_edit_works() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = get_test_tree(cipher_suite).public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(leaf_nodes.clone()).unwrap();

        let acc = tree
            .batch_edit(
                BatchAccumulator::default(),
                &[(LeafIndex(0), get_basic_test_node(cipher_suite, "A"))],
                &[LeafIndex(1)],
                &[get_basic_test_node(cipher_suite, "D")],
            )
            .unwrap();

        assert_eq!(acc.additions, [LeafIndex(1)]);
        assert_eq!(acc.removals, [(LeafIndex(1), leaf_nodes[0].clone())]);
        assert_eq!(acc.updates, [LeafIndex(0)]);
    }
}
