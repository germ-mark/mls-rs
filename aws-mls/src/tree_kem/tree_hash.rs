use super::leaf_node::LeafNode;
use super::node::LeafIndex;
use super::tree_math::{BfsIterBottomUp, BfsIterTopDown};
use crate::provider::crypto::CipherSuiteProvider;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::Parent;
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use std::collections::{HashMap, VecDeque};
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct TreeHashes {
    pub current: Vec<Vec<u8>>,
    pub original: Vec<Vec<u8>>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct LeafNodeHashInput<'a> {
    node_index: u32,
    leaf_node: Option<&'a LeafNode>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct ParentNodeTreeHashInput<'a> {
    node_index: u32,
    parent_node: Option<&'a Parent>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    left_hash: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    right_hash: &'a [u8],
}

#[derive(Debug, TlsSerialize, TlsSize)]
#[repr(u8)]
enum TreeHashInput<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(LeafNodeHashInput<'a>),
    Parent(ParentNodeTreeHashInput<'a>),
}

impl TreeHashes {
    pub fn hash_for_leaf<P: CipherSuiteProvider>(
        &self,
        node_index: u32,
        leaf_node: Option<&LeafNode>,
        cipher_suite_provider: &P,
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let input = TreeHashInput::Leaf(LeafNodeHashInput {
            node_index,
            leaf_node,
        });

        cipher_suite_provider
            .hash(&input.tls_serialize_detached()?)
            .map_err(|e| RatchetTreeError::CipherSuiteProviderError(e.into()))
    }

    pub fn hash_for_parent<P: CipherSuiteProvider>(
        &self,
        node_index: u32,
        parent_node: Option<&Parent>,
        cipher_suite_provider: &P,
        filtered: &[LeafIndex],
        left_hash: &[u8],
        right_hash: &[u8],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let mut parent_node = parent_node.cloned();

        if let Some(ref mut parent_node) = parent_node {
            parent_node
                .unmerged_leaves
                .retain(|unmerged_index| !filtered.contains(unmerged_index));
        }

        let input = TreeHashInput::Parent(ParentNodeTreeHashInput {
            node_index,
            parent_node: parent_node.as_ref(),
            left_hash,
            right_hash,
        });

        cipher_suite_provider
            .hash(&input.tls_serialize_detached()?)
            .map_err(|e| RatchetTreeError::CipherSuiteProviderError(e.into()))
    }
}

impl TreeKemPublic {
    pub fn tree_hash<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
    ) -> Result<Vec<u8>, RatchetTreeError>
    where
        P: CipherSuiteProvider,
    {
        self.initialize_hashes(cipher_suite_provider)?;
        let root = tree_math::root(self.total_leaf_count());
        Ok(self.tree_hashes.current[root as usize].clone())
    }

    // Update hashes after `committer` makes changes to the tree. `path_blank` is the
    // list of leaves whose paths were blanked, i.e. updates and removes.
    pub fn update_hashes<P: CipherSuiteProvider>(
        &mut self,
        path_blanked: &mut Vec<LeafIndex>,
        leaves_added: &[LeafIndex],
        cipher_suite_provider: &P,
    ) -> Result<(), RatchetTreeError>
    where
        P: CipherSuiteProvider,
    {
        self.initialize_hashes(cipher_suite_provider)?;

        // Update the current hashes for direct paths of all modified leaves.
        self.update_current_hashes(
            path_blanked.iter().chain(leaves_added.iter()),
            cipher_suite_provider,
        )?;

        // Update original hashes for the committer and nodes with blanked paths.
        let num_leaves = self.total_leaf_count();

        if self.nodes.len() <= 1 {
            return Ok(());
        }

        // Resize hashes in case the tree was extended or truncated.
        self.tree_hashes
            .original
            .resize((num_leaves * 2 - 1) as usize, vec![]);

        // In case the tree was extended, we have to compute additional hashes on the right.
        let mut node_index: i32 = (2 * num_leaves - 2) as i32;
        while node_index >= 0 && self.tree_hashes.current[node_index as usize].is_empty() {
            path_blanked.push(LeafIndex((node_index / 2) as u32));
            node_index -= 2;
        }

        // For each affected leaf, the original hashes on its path and copath become the current hashes,
        // at the time of the current commit.
        for &LeafIndex(leaf_index) in path_blanked.iter() {
            if leaf_index >= self.nodes.total_leaf_count() {
                continue;
            }
            let node_index = 2 * (leaf_index);
            let path = tree_math::direct_path(node_index, num_leaves)?.into_iter();
            let copath = tree_math::copath(node_index, num_leaves)?.into_iter();
            for n in path.chain(copath).chain([node_index].into_iter()) {
                self.tree_hashes.original[n as usize] =
                    self.tree_hashes.current[n as usize].clone();
            }
        }

        Ok(())
    }

    // Initialize all hashes after creating / importing a tree.
    fn initialize_hashes<P>(&mut self, cipher_suite_provider: &P) -> Result<(), RatchetTreeError>
    where
        P: CipherSuiteProvider,
    {
        if self.tree_hashes.current.is_empty() {
            self.update_current_hashes(vec![].into_iter(), cipher_suite_provider)?;
            if self.nodes.len() > 1 {
                self.initialize_original_hashes(cipher_suite_provider)?;
            }
        }
        Ok(())
    }

    fn update_current_hashes<'a, P: CipherSuiteProvider>(
        &mut self,
        leaf_indices: impl Iterator<Item = &'a LeafIndex>,
        cipher_suite_provider: &P,
    ) -> Result<(), RatchetTreeError> {
        let num_leaves = self.total_leaf_count();
        let root = tree_math::root(num_leaves);

        // Resize the array in case the tree was extended or truncated
        self.tree_hashes
            .current
            .resize((num_leaves * 2 - 1) as usize, vec![]);

        let mut nodes = VecDeque::from_iter(
            leaf_indices
                .filter_map(|l| (**l < num_leaves).then_some(**l * 2))
                .chain((0..num_leaves).rev().map_while(|l| {
                    self.tree_hashes.current[2 * l as usize]
                        .is_empty()
                        .then_some(l * 2)
                })),
        );

        while let Some(n) = nodes.front().copied().filter(|&n| n & 1 == 0) {
            let _ = nodes.pop_front();

            self.tree_hashes.current[n as usize] = self.tree_hashes.hash_for_leaf(
                n,
                self.nodes.borrow_as_leaf(LeafIndex(n / 2)).ok(),
                cipher_suite_provider,
            )?;

            if n != root {
                nodes.push_back(tree_math::parent(n, num_leaves)?);
            }
        }

        let mut hash_computed = vec![false; (2 * num_leaves - 1) as usize];

        while let Some(n) = nodes.pop_front() {
            self.tree_hashes.current[n as usize] = self.tree_hashes.hash_for_parent(
                n,
                self.nodes.borrow_as_parent(n).ok(),
                cipher_suite_provider,
                &[],
                &self.tree_hashes.current[tree_math::left(n)? as usize],
                &self.tree_hashes.current[tree_math::right(n)? as usize],
            )?;

            hash_computed[n as usize] = true;

            if let Ok(p) = tree_math::parent(n, num_leaves) {
                if !hash_computed[p as usize] {
                    nodes.push_back(p);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn unmerged_in_subtree(
        &self,
        node_unmerged: u32,
        subtree_root: u32,
    ) -> Result<&[LeafIndex], RatchetTreeError> {
        let unmerged = &self.nodes.borrow_as_parent(node_unmerged)?.unmerged_leaves;
        let (left, right) = tree_math::subtree(subtree_root);
        let mut start = 0;
        while start < unmerged.len() && unmerged[start] < left {
            start += 1;
        }
        let mut end = start;
        while end < unmerged.len() && unmerged[end] < right {
            end += 1;
        }
        Ok(&unmerged[start..end])
    }

    fn different_unmerged(&self, ancestor: u32, descendant: u32) -> Result<bool, RatchetTreeError> {
        Ok(!self.nodes.is_blank(ancestor)?
            && !self.nodes.is_blank(descendant)?
            && self.unmerged_in_subtree(ancestor, descendant)?
                != self.nodes.borrow_as_parent(descendant)?.unmerged_leaves)
    }

    fn initialize_original_hashes<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
    ) -> Result<(), RatchetTreeError> {
        let num_leaves = self.nodes.total_leaf_count() as usize;
        let root = tree_math::root(num_leaves as u32);

        // The value `filtered_sets[n]` is a list of all ancestors `a` of `n` s.t. we have to compute
        // the tree hash of `n` with the unmerged leaves of `a` filtered out.
        let mut filtered_sets = vec![vec![]; num_leaves * 2 - 1];
        filtered_sets[root as usize].push(root);

        let bfs_iter = BfsIterTopDown::new(num_leaves).skip(1);

        for n in bfs_iter {
            let p = tree_math::parent(n as u32, num_leaves as u32)?;
            filtered_sets[n] = filtered_sets[p as usize].clone();
            if self.different_unmerged(*filtered_sets[p as usize].last().unwrap(), p)? {
                filtered_sets[n].push(p);
            }
        }

        // The value `hashes[n][a]` is the tree hash of `n` with the unmerged leaves of `n` filtered out.
        let mut hashes: Vec<HashMap<u32, Vec<u8>>> = vec![HashMap::new(); num_leaves * 2 - 1];
        let mut bfs_iterator = BfsIterBottomUp::new(num_leaves);

        // First, compute `hashes[l]` for each leaf `l`.
        bfs_iterator
            .by_ref()
            .take(self.nodes.total_leaf_count() as usize)
            .try_for_each(|index| {
                for a in filtered_sets[index].iter() {
                    let leaf_index = LeafIndex(index as u32 / 2);

                    let filter_leaf = !self.nodes.is_blank(*a)?
                        && self
                            .nodes
                            .borrow_as_parent(*a)?
                            .unmerged_leaves
                            .contains(&leaf_index);

                    let hash = self.tree_hashes.hash_for_leaf(
                        index as u32,
                        if filter_leaf {
                            None
                        } else {
                            self.nodes.borrow_as_leaf(leaf_index).ok()
                        },
                        cipher_suite_provider,
                    )?;

                    hashes[index].insert(*a, hash);
                }
                Ok::<_, RatchetTreeError>(())
            })?;

        // Then, compute `hashes[n]` for each internal node `n`, traversing the tree bottom-up.
        for n in bfs_iterator {
            for a in &filtered_sets[n] {
                let left_hash = hashes[tree_math::left(n as u32)? as usize][a].clone();
                let right_hash = hashes[tree_math::right(n as u32)? as usize][a].clone();

                let filtered = self
                    .nodes
                    .borrow_as_parent(*a)
                    .map_or(Vec::new(), |node| node.unmerged_leaves.clone());

                let hash = self.tree_hashes.hash_for_parent(
                    n as u32,
                    self.nodes.borrow_as_parent(n as u32).ok(),
                    cipher_suite_provider,
                    &filtered,
                    &left_hash,
                    &right_hash,
                )?;

                hashes[n].insert(*a, hash);
            }
        }

        // Set the `original_hashes` based on the computed `hashes`.
        self.tree_hashes.original.resize(num_leaves * 2 - 1, vec![]);
        for (i, hash) in self.tree_hashes.original.iter_mut().enumerate() {
            let a = filtered_sets[i].last().unwrap();
            *hash = if self.nodes.is_blank(*a)? {
                self.tree_hashes.current[i].clone()
            } else {
                hashes[i][a].clone()
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tls_codec::Deserialize;

    use crate::{
        cipher_suite::CipherSuite,
        provider::{
            crypto::test_utils::{test_cipher_suite_provider, try_test_cipher_suite_provider},
            identity::BasicIdentityProvider,
        },
        tree_kem::{node::NodeVec, parent_hash::test_utils::get_test_tree_fig_12},
    };

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        tree_data: Vec<u8>,
        #[serde(with = "hex::serde")]
        tree_hash: Vec<u8>,
    }

    impl TestCase {
        async fn generate() -> Vec<TestCase> {
            futures::stream::iter(CipherSuite::all())
                .then(|cipher_suite| async move {
                    let mut tree = get_test_tree_fig_12(cipher_suite).await;

                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        tree_data: tree.export_node_data().tls_serialize_detached().unwrap(),
                        tree_hash: tree
                            .tree_hash(&test_cipher_suite_provider(cipher_suite))
                            .unwrap(),
                    }
                })
                .collect()
                .await
        }
    }

    async fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(tree_hash, TestCase::generate().await)
    }

    #[futures_test::test]
    async fn test_tree_hash() {
        let cases = load_test_cases().await;

        for one_case in cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                continue;
            };

            let mut tree = TreeKemPublic::import_node_data(
                NodeVec::tls_deserialize(&mut &*one_case.tree_data).unwrap(),
                &BasicIdentityProvider,
            )
            .await
            .unwrap();

            let calculated_hash = tree.tree_hash(&cs_provider).unwrap();

            assert_eq!(calculated_hash, one_case.tree_hash);
        }
    }
}