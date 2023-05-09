use alloc::string::String;
use alloc::{format, vec};
use core::borrow::BorrowMut;

use debug_tree::TreeBuilder;

use super::node::NodeIndex;
use super::{math::root, node::NodeVec};
use crate::client::MlsError;
use crate::tree_kem::math::{left, right};

pub(crate) fn build_tree(
    tree: &mut TreeBuilder,
    nodes: &NodeVec,
    idx: NodeIndex,
) -> Result<(), MlsError> {
    let blank_tag = if nodes.is_blank(idx)? { "Blank " } else { "" };

    // Leaf Node
    if nodes.is_leaf(idx) {
        let leaf_tag = format!("{blank_tag}Leaf ({idx})");
        tree.add_leaf(&leaf_tag);
        return Ok(());
    }

    // Parent Leaf
    let mut parent_tag = format!("{blank_tag}Parent ({idx})");

    if root(nodes.total_leaf_count()) == idx {
        parent_tag = format!("{blank_tag}Root ({idx})");
    }

    // Add unmerged leaves indexes
    let unmerged_leaves_idxs = match nodes.borrow_as_parent(idx) {
        Ok(parent) => parent
            .unmerged_leaves
            .iter()
            .map(|leaf_idx| format!("{}", leaf_idx.0))
            .collect(),
        Err(_) => {
            // Empty parent nodes throw `NotParent` error when borrow as Parent
            vec![]
        }
    };

    if !unmerged_leaves_idxs.is_empty() {
        let unmerged_leaves_tag =
            format!(" unmerged leaves idxs: {}", unmerged_leaves_idxs.join(","));
        parent_tag.push_str(&unmerged_leaves_tag);
    }

    let mut branch = tree.add_branch(&parent_tag);

    build_tree(tree, nodes, left(idx)?)?;
    build_tree(tree, nodes, right(idx)?)?;

    branch.release();

    Ok(())
}

pub(crate) fn build_ascii_tree(nodes: &NodeVec) -> String {
    let leaves_count: u32 = nodes.total_leaf_count();
    let mut tree = TreeBuilder::new();
    build_tree(tree.borrow_mut(), nodes, root(leaves_count)).unwrap();
    tree.string()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::test_cipher_suite_provider,
        identity::basic::BasicIdentityProvider,
        tree_kem::{
            node::Parent,
            parent_hash::ParentHash,
            test_utils::{get_test_leaf_nodes, get_test_tree},
        },
    };

    use super::build_ascii_tree;

    #[futures_test::test]
    async fn print_fully_populated_tree() {
        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, &BasicIdentityProvider)
            .await
            .unwrap();

        let tree_str = concat!(
            "Blank Root (3)\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }

    #[futures_test::test]
    async fn print_tree_blank_leaves() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        let to_remove = tree
            .add_leaves(key_packages, &BasicIdentityProvider)
            .await
            .unwrap()[0];

        tree.remove_leaves(
            vec![to_remove],
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let tree_str = concat!(
            "Blank Root (3)\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Blank Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }

    #[futures_test::test]
    async fn print_tree_unmerged_leaves_on_parent() {
        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            [key_packages[0].clone(), key_packages[1].clone()].to_vec(),
            &BasicIdentityProvider,
        )
        .await
        .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_leaves([key_packages[2].clone()].to_vec(), &BasicIdentityProvider)
            .await
            .unwrap();

        let tree_str = concat!(
            "Root (3) unmerged leaves idxs: 3\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }
}
