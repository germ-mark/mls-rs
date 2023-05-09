use super::*;
use crate::{
    group::proposal_filter::{
        FailInvalidProposal, IgnoreInvalidByRefProposal, ProposalApplier, ProposalBundle,
        ProposalRules, ProposalSource, ProposalState,
    },
    time::MlsTime,
    tree_kem::leaf_node::LeafNode,
};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use aws_mls_core::{error::IntoAnyError, psk::PreSharedKeyStorage};

#[derive(Debug, PartialEq)]
pub(crate) struct ProposalSetEffects {
    pub tree: TreeKemPublic,
    pub added_leaf_indexes: Vec<LeafIndex>,
    pub removed_leaves: Vec<(LeafIndex, LeafNode)>,
    pub adds: Vec<KeyPackage>,
    pub updates: Vec<(LeafIndex, LeafNode)>,
    pub removes: Vec<LeafIndex>,
    pub group_context_ext: Option<ExtensionList>,
    pub psks: Vec<PreSharedKeyID>,
    pub reinit: Option<ReInitProposal>,
    #[cfg(feature = "external_commit")]
    pub external_init: Option<(LeafIndex, ExternalInit)>,
    #[cfg(all(feature = "state_update", feature = "custom_proposal"))]
    pub custom_proposals: Vec<CustomProposal>,
    #[cfg(feature = "state_update")]
    pub rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

impl ProposalSetEffects {
    pub fn new(
        tree: TreeKemPublic,
        added_leaf_indexes: Vec<LeafIndex>,
        removed_leaves: Vec<(LeafIndex, LeafNode)>,
        proposals: ProposalBundle,
        #[cfg(feature = "external_commit")] external_leaf: Option<LeafIndex>,
        #[cfg(feature = "state_update")] rejected_proposals: Vec<(ProposalRef, Proposal)>,
    ) -> Result<Self, MlsError> {
        let mut init = ProposalSetEffects {
            tree,
            added_leaf_indexes,
            removed_leaves,
            adds: Vec::new(),
            updates: Vec::new(),
            removes: Vec::new(),
            group_context_ext: None,
            psks: Vec::new(),
            reinit: None,
            #[cfg(feature = "external_commit")]
            external_init: None,
            #[cfg(feature = "state_update")]
            rejected_proposals,
            #[cfg(all(feature = "custom_proposal", feature = "state_update"))]
            custom_proposals: Vec::new(),
        };

        for item in proposals.into_proposals() {
            match item.proposal {
                Proposal::Add(add) => init.adds.push(add.key_package),
                Proposal::Update(update) => {
                    if let Sender::Member(package_to_replace) = item.sender {
                        init.updates
                            .push((LeafIndex(package_to_replace), update.leaf_node))
                    }
                }
                Proposal::Remove(remove) => init.removes.push(remove.to_remove),
                Proposal::GroupContextExtensions(list) => init.group_context_ext = Some(list),
                Proposal::Psk(PreSharedKeyProposal { psk }) => {
                    init.psks.push(psk);
                }
                Proposal::ReInit(reinit) => {
                    init.reinit = Some(reinit);
                }
                #[cfg(feature = "external_commit")]
                Proposal::ExternalInit(external_init) => {
                    let new_member_leaf_index = external_leaf.ok_or(MlsError::CommitMissingPath)?;

                    init.external_init = Some((new_member_leaf_index, external_init));
                }
                #[cfg(all(feature = "state_update", feature = "custom_proposal"))]
                Proposal::Custom(custom) => init.custom_proposals.push(custom),
                #[cfg(all(not(feature = "state_update"), feature = "custom_proposal"))]
                Proposal::Custom(_) => (),
            };
        }

        Ok(init)
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(not(feature = "external_commit"))]
        let res = true;

        #[cfg(feature = "external_commit")]
        let res = self.external_init.is_none();

        res && self.adds.is_empty()
            && self.updates.is_empty()
            && self.removes.is_empty()
            && self.group_context_ext.is_none()
            && self.psks.is_empty()
            && self.reinit.is_none()
    }

    //By default, the path field of a Commit MUST be populated. The path field MAY be omitted if
    //(a) it covers at least one proposal and (b) none of the proposals covered by the Commit are
    //of "path required" types. A proposal type requires a path if it cannot change the group
    //membership in a way that requires the forward secrecy and post-compromise security guarantees
    //that an UpdatePath provides. The only proposal types defined in this document that do not
    //require a path are:

    // add
    // psk
    // reinit
    pub fn path_update_required(&self) -> bool {
        #[cfg(feature = "external_commit")]
        let res = self.external_init.is_some();

        #[cfg(not(feature = "external_commit"))]
        let res = false;

        res || self.is_empty()
            || self.group_context_ext.is_some()
            || !self.updates.is_empty()
            || !self.removes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CachedProposal {
    proposal: Proposal,
    sender: Sender,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProposalCache {
    protocol_version: ProtocolVersion,
    group_id: Vec<u8>,
    #[cfg(feature = "std")]
    proposals: HashMap<ProposalRef, CachedProposal>,
    #[cfg(not(feature = "std"))]
    proposals: BTreeMap<ProposalRef, CachedProposal>,
}

impl ProposalCache {
    pub fn new(protocol_version: ProtocolVersion, group_id: Vec<u8>) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals: Default::default(),
        }
    }

    pub fn import(
        protocol_version: ProtocolVersion,
        group_id: Vec<u8>,
        #[cfg(feature = "std")] proposals: HashMap<ProposalRef, CachedProposal>,
        #[cfg(not(feature = "std"))] proposals: BTreeMap<ProposalRef, CachedProposal>,
    ) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.proposals.clear();
    }

    #[cfg(feature = "private_message")]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    pub fn insert(&mut self, proposal_ref: ProposalRef, proposal: Proposal, sender: Sender) {
        let cached_proposal = CachedProposal { proposal, sender };
        self.proposals.insert(proposal_ref, cached_proposal);
    }

    #[cfg(feature = "std")]
    #[inline]
    pub fn proposals(&self) -> &HashMap<ProposalRef, CachedProposal> {
        &self.proposals
    }

    #[cfg(not(feature = "std"))]
    #[inline]
    pub fn proposals(&self) -> &BTreeMap<ProposalRef, CachedProposal> {
        &self.proposals
    }

    #[cfg(feature = "custom_proposal")]
    pub async fn expand_custom_proposals<F>(
        &self,
        roster: &[Member],
        group_extensions: &ExtensionList,
        proposal_bundle: &mut ProposalBundle,
        user_rules: &F,
    ) -> Result<(), MlsError>
    where
        F: ProposalRules,
    {
        let new_proposals = user_rules
            .expand_custom_proposals(roster, group_extensions, proposal_bundle.custom_proposals())
            .await
            .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;

        new_proposals
            .into_iter()
            .for_each(|info| proposal_bundle.add(info.proposal, info.sender, info.source));

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_commit<C, F, P, CSP>(
        &self,
        sender: Sender,
        additional_proposals: Vec<Proposal>,
        group_extensions: &ExtensionList,
        identity_provider: &C,
        cipher_suite_provider: &CSP,
        public_tree: &TreeKemPublic,
        #[cfg(feature = "external_commit")] external_leaf: Option<&LeafNode>,
        psk_storage: &P,
        user_filter: F,
        roster: &[Member],
    ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), MlsError>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        let proposals = self
            .proposals
            .iter()
            .map(|(proposal_ref, proposal)| {
                (
                    proposal.proposal.clone(),
                    proposal.sender,
                    ProposalSource::ByReference(proposal_ref.clone()),
                )
            })
            .chain(
                additional_proposals
                    .into_iter()
                    .map(|p| (p, sender, ProposalSource::ByValue)),
            )
            .fold(
                ProposalBundle::default(),
                |mut proposals, (proposal, sender, proposal_ref)| {
                    proposals.add(proposal, sender, proposal_ref);
                    proposals
                },
            );

        let proposals = user_filter
            .filter(sender, roster, group_extensions, proposals)
            .await
            .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;

        #[cfg(feature = "custom_proposal")]
        let mut proposals = proposals;

        #[cfg(feature = "custom_proposal")]
        self.expand_custom_proposals(roster, group_extensions, &mut proposals, &user_filter)
            .await?;

        let required_capabilities = group_extensions.get_as()?;

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            cipher_suite_provider,
            &self.group_id,
            group_extensions,
            required_capabilities.as_ref(),
            #[cfg(feature = "external_commit")]
            external_leaf,
            identity_provider,
            psk_storage,
        );

        #[cfg(feature = "std")]
        let time = Some(MlsTime::now());

        #[cfg(not(feature = "std"))]
        let time = None;

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            #[cfg(feature = "external_commit")]
            external_leaf_index,
        } = applier
            .apply_proposals(&IgnoreInvalidByRefProposal, &sender, proposals, time)
            .await?;

        #[cfg(feature = "state_update")]
        let rejected = rejected_proposals(self.proposals.clone(), &proposals, &sender);

        let effects = ProposalSetEffects::new(
            tree,
            added_indexes,
            removed_leaves,
            proposals.clone(),
            #[cfg(feature = "external_commit")]
            external_leaf_index,
            #[cfg(feature = "state_update")]
            rejected,
        )?;

        let proposals = proposals.into_proposals_or_refs().collect();
        Ok((proposals, effects))
    }

    fn resolve_item(
        &self,
        sender: Sender,
        proposal: ProposalOrRef,
    ) -> Result<CachedProposal, MlsError> {
        match proposal {
            ProposalOrRef::Proposal(proposal) => Ok(CachedProposal { proposal, sender }),
            ProposalOrRef::Reference(proposal_ref) => self
                .proposals
                .get(&proposal_ref)
                .cloned()
                .ok_or(MlsError::ProposalNotFound(proposal_ref)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_for_commit<C, F, P, CSP>(
        &self,
        sender: Sender,
        #[cfg(feature = "state_update")] receiver: Option<LeafIndex>,
        proposal_list: Vec<ProposalOrRef>,
        #[cfg(feature = "external_commit")] external_leaf: Option<&LeafNode>,
        group_extensions: &ExtensionList,
        identity_provider: &C,
        cipher_suite_provider: &CSP,
        public_tree: &TreeKemPublic,
        psk_storage: &P,
        user_rules: F,
        commit_time: Option<MlsTime>,
        roster: &[Member],
    ) -> Result<ProposalSetEffects, MlsError>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        let proposals = proposal_list.into_iter().try_fold(
            ProposalBundle::default(),
            |mut proposals, proposal| {
                let proposal_source = match &proposal {
                    ProposalOrRef::Reference(r) => ProposalSource::ByReference(r.clone()),
                    ProposalOrRef::Proposal(_) => ProposalSource::ByValue,
                };

                let proposal = self.resolve_item(sender, proposal)?;
                proposals.add(proposal.proposal, proposal.sender, proposal_source);
                Ok::<_, MlsError>(proposals)
            },
        )?;

        user_rules
            .validate(sender, roster, group_extensions, &proposals)
            .await
            .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;

        #[cfg(feature = "custom_proposal")]
        let mut proposals = proposals;

        #[cfg(feature = "custom_proposal")]
        self.expand_custom_proposals(roster, group_extensions, &mut proposals, &user_rules)
            .await?;

        let required_capabilities = group_extensions.get_as()?;

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            cipher_suite_provider,
            &self.group_id,
            group_extensions,
            required_capabilities.as_ref(),
            #[cfg(feature = "external_commit")]
            external_leaf,
            identity_provider,
            psk_storage,
        );

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            #[cfg(feature = "external_commit")]
            external_leaf_index,
        } = applier
            .apply_proposals(&FailInvalidProposal, &sender, proposals, commit_time)
            .await?;

        #[cfg(feature = "state_update")]
        let rejected = receiver
            .map(|index| {
                rejected_proposals(self.proposals.clone(), &proposals, &Sender::Member(*index))
            })
            .unwrap_or_default();

        ProposalSetEffects::new(
            tree,
            added_indexes,
            removed_leaves,
            proposals,
            #[cfg(feature = "external_commit")]
            external_leaf_index,
            #[cfg(feature = "state_update")]
            rejected,
        )
    }
}

impl Extend<(ProposalRef, CachedProposal)> for ProposalCache {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (ProposalRef, CachedProposal)>,
    {
        self.proposals.extend(iter);
    }
}

#[cfg(feature = "state_update")]
fn rejected_proposals(
    #[cfg(feature = "std")] mut cache: HashMap<ProposalRef, CachedProposal>,
    #[cfg(not(feature = "std"))] mut cache: BTreeMap<ProposalRef, CachedProposal>,
    accepted_proposals: &ProposalBundle,
    sender: &Sender,
) -> Vec<(ProposalRef, Proposal)> {
    accepted_proposals
        .iter_proposals()
        .filter_map(|p| match p.source {
            ProposalSource::ByReference(reference) => Some(reference),
            _ => None,
        })
        .for_each(|r| {
            cache.remove(&r);
        });

    cache
        .into_iter()
        .filter(|(_, p)| p.sender == *sender)
        .map(|(r, p)| (r, p.proposal))
        .collect()
}

#[cfg(test)]
pub(crate) mod test_utils {

    use aws_mls_core::{
        crypto::CipherSuiteProvider, extension::ExtensionList, identity::IdentityProvider,
        psk::PreSharedKeyStorage,
    };

    use crate::{
        client::test_utils::TEST_PROTOCOL_VERSION,
        group::{
            internal::{LeafIndex, TreeKemPublic},
            proposal::{Proposal, ProposalOrRef},
            proposal_filter::{PassThroughProposalRules, ProposalRules},
            proposal_ref::ProposalRef,
            test_utils::TEST_GROUP,
            Sender,
        },
        identity::{basic::BasicIdentityProvider, test_utils::BasicWithCustomProvider},
        psk::AlwaysFoundPskStorage,
    };

    use super::{CachedProposal, MlsError, ProposalCache, ProposalSetEffects};

    impl CachedProposal {
        pub fn new(proposal: Proposal, sender: Sender) -> Self {
            Self { proposal, sender }
        }
    }

    #[derive(Debug)]
    pub(crate) struct CommitReceiver<'a, C, F, P, CSP> {
        tree: &'a TreeKemPublic,
        sender: Sender,
        receiver: LeafIndex,
        cache: ProposalCache,
        identity_provider: C,
        cipher_suite_provider: CSP,
        group_context_extensions: ExtensionList,
        user_rules: F,
        with_psk_storage: P,
    }

    impl<'a, CSP>
        CommitReceiver<
            'a,
            BasicWithCustomProvider,
            PassThroughProposalRules,
            AlwaysFoundPskStorage,
            CSP,
        >
    {
        pub fn new<S>(
            tree: &'a TreeKemPublic,
            sender: S,
            receiver: LeafIndex,
            cipher_suite_provider: CSP,
        ) -> Self
        where
            S: Into<Sender>,
        {
            Self {
                tree,
                sender: sender.into(),
                receiver,
                cache: make_proposal_cache(),
                identity_provider: BasicWithCustomProvider::new(BasicIdentityProvider),
                group_context_extensions: Default::default(),
                user_rules: pass_through_rules(),
                with_psk_storage: AlwaysFoundPskStorage,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitReceiver<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        #[cfg(feature = "external_proposal")]
        pub fn with_identity_provider<V>(self, validator: V) -> CommitReceiver<'a, V, F, P, CSP>
        where
            V: IdentityProvider,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: validator,
                group_context_extensions: self.group_context_extensions,
                user_rules: self.user_rules,
                with_psk_storage: self.with_psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        pub fn with_user_rules<G>(self, f: G) -> CommitReceiver<'a, C, G, P, CSP>
        where
            G: ProposalRules,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_rules: f,
                with_psk_storage: self.with_psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        pub fn with_psk_storage<V>(self, v: V) -> CommitReceiver<'a, C, F, V, CSP>
        where
            V: PreSharedKeyStorage,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_rules: self.user_rules,
                with_psk_storage: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        #[cfg(feature = "external_proposal")]
        pub fn with_extensions(self, extensions: ExtensionList) -> Self {
            Self {
                group_context_extensions: extensions,
                ..self
            }
        }

        pub fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        pub async fn receive<I>(&self, proposals: I) -> Result<ProposalSetEffects, MlsError>
        where
            I: IntoIterator,
            I::Item: Into<ProposalOrRef>,
        {
            self.cache
                .resolve_for_commit_default(
                    self.sender,
                    #[cfg(feature = "state_update")]
                    Some(self.receiver),
                    proposals.into_iter().map(Into::into).collect(),
                    None,
                    &self.group_context_extensions,
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    &self.with_psk_storage,
                    &self.user_rules,
                )
                .await
        }
    }

    pub(crate) fn make_proposal_cache() -> ProposalCache {
        ProposalCache::new(TEST_PROTOCOL_VERSION, TEST_GROUP.to_vec())
    }

    pub fn pass_through_rules() -> PassThroughProposalRules {
        PassThroughProposalRules::new()
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::{pass_through_rules, CommitReceiver};
    use super::*;
    use super::{
        proposal_ref::test_utils::auth_content_from_proposal, test_utils::make_proposal_cache,
    };
    use crate::tree_kem::leaf_node::test_utils::{
        get_basic_test_node_capabilities, get_test_capabilities,
    };
    use crate::tree_kem::leaf_node::LeafNodeSigningContext;
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        crypto::{self, test_utils::test_cipher_suite_provider},
        extension::{test_utils::TestExtension, RequiredCapabilitiesExt},
        group::{
            proposal_filter::proposer_can_propose,
            test_utils::{random_bytes, test_group, TEST_GROUP},
        },
        identity::basic::BasicIdentityProvider,
        identity::test_utils::{get_test_signing_identity, BasicWithCustomProvider},
        key_package::{
            test_utils::{test_key_package, test_key_package_custom},
            KeyPackageGenerator,
        },
        psk::AlwaysFoundPskStorage,
        tree_kem::{
            leaf_node::{
                test_utils::{
                    default_properties, get_basic_test_node, get_basic_test_node_sig_key,
                },
                ConfigProperties, LeafNodeSource,
            },
            parent_hash::ParentHash,
            Lifetime,
        },
    };

    #[cfg(feature = "external_proposal")]
    use crate::{
        extension::ExternalSendersExt,
        tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider,
    };

    use assert_matches::assert_matches;
    use aws_mls_core::psk::PreSharedKey;
    use aws_mls_core::{
        extension::MlsExtension,
        identity::{BasicCredential, Credential, CredentialType, CustomCredential},
    };
    use core::convert::Infallible;
    use futures::FutureExt;
    use internal::proposal_filter::{PassThroughProposalRules, ProposalInfo};
    use itertools::Itertools;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    impl ProposalCache {
        #[allow(clippy::too_many_arguments)]
        pub async fn resolve_for_commit_default<C, F, P, CSP>(
            &self,
            sender: Sender,
            #[cfg(feature = "state_update")] receiver: Option<LeafIndex>,
            proposal_list: Vec<ProposalOrRef>,
            external_leaf: Option<&LeafNode>,
            group_extensions: &ExtensionList,
            identity_provider: &C,
            cipher_suite_provider: &CSP,
            public_tree: &TreeKemPublic,
            psk_storage: &P,
            user_rules: F,
        ) -> Result<ProposalSetEffects, MlsError>
        where
            C: IdentityProvider,
            F: ProposalRules,
            P: PreSharedKeyStorage,
            CSP: CipherSuiteProvider,
        {
            self.resolve_for_commit(
                sender,
                #[cfg(feature = "state_update")]
                receiver,
                proposal_list,
                #[cfg(feature = "external_commit")]
                external_leaf,
                group_extensions,
                identity_provider,
                cipher_suite_provider,
                public_tree,
                psk_storage,
                user_rules,
                None,
                &[],
            )
            .await
        }
    }

    fn test_sender() -> u32 {
        1
    }

    async fn new_tree_custom_proposals(
        name: &str,
        proposal_types: Vec<ProposalType>,
    ) -> (LeafIndex, TreeKemPublic) {
        let (leaf, secret, _) = get_basic_test_node_capabilities(
            TEST_CIPHER_SUITE,
            name,
            Capabilities {
                proposals: proposal_types,
                ..get_test_capabilities()
            },
        )
        .await;

        let (pub_tree, priv_tree) = TreeKemPublic::derive(leaf, secret, &BasicIdentityProvider)
            .await
            .unwrap();

        (priv_tree.self_index, pub_tree)
    }

    async fn new_tree(name: &str) -> (LeafIndex, TreeKemPublic) {
        new_tree_custom_proposals(name, vec![]).await
    }

    async fn add_member(tree: &mut TreeKemPublic, name: &str) -> LeafIndex {
        tree.add_leaves(
            vec![get_basic_test_node(TEST_CIPHER_SUITE, name).await],
            &BasicIdentityProvider,
        )
        .await
        .unwrap()[0]
    }

    async fn update_leaf_node(name: &str, leaf_index: u32) -> LeafNode {
        let (mut leaf, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name).await;

        leaf.update(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            TEST_GROUP,
            leaf_index,
            default_properties(),
            None,
            &signer,
        )
        .unwrap();

        leaf
    }

    struct TestProposals {
        test_sender: u32,
        test_proposals: Vec<AuthenticatedContent>,
        expected_effects: ProposalSetEffects,
        tree: TreeKemPublic,
    }

    async fn test_proposals(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestProposals {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let (sender_leaf, sender_leaf_secret, _) =
            get_basic_test_node_sig_key(cipher_suite, "alice").await;

        let sender = LeafIndex(0);

        let (mut tree, _) =
            TreeKemPublic::derive(sender_leaf, sender_leaf_secret, &BasicIdentityProvider)
                .await
                .unwrap();

        let add_package = test_key_package(protocol_version, cipher_suite, "dave").await;

        let remove_leaf_index = add_member(&mut tree, "carol").await;

        let add = Proposal::Add(AddProposal {
            key_package: add_package.clone(),
        });

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: remove_leaf_index,
        });

        let extensions = Proposal::GroupContextExtensions(ExtensionList::new());

        let proposals = vec![add, remove, extensions];

        let test_sender = *tree
            .add_leaves(
                vec![get_basic_test_node(cipher_suite, "charlie").await],
                &BasicIdentityProvider,
            )
            .await
            .unwrap()[0];

        let mut expected_tree = tree.clone();

        let mut bundle = ProposalBundle::default();

        proposals.iter().cloned().for_each(|p| {
            bundle.add(
                p,
                Sender::Member(test_sender),
                ProposalSource::ByReference(ProposalRef::new_fake(vec![])),
            )
        });

        expected_tree
            .batch_edit(
                &mut bundle,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                true,
            )
            .await
            .unwrap();

        let effects = ProposalSetEffects {
            tree: expected_tree,
            added_leaf_indexes: vec![LeafIndex(1)],
            removed_leaves: vec![(
                remove_leaf_index,
                tree.get_leaf_node(remove_leaf_index).unwrap().clone(),
            )],
            adds: vec![add_package],
            updates: vec![],
            removes: vec![remove_leaf_index],
            group_context_ext: Some(ExtensionList::new()),
            psks: Vec::new(),
            reinit: None,
            #[cfg(feature = "external_commit")]
            external_init: None,
            #[cfg(feature = "state_update")]
            rejected_proposals: Vec::new(),
            #[cfg(all(feature = "state_update", feature = "custom_proposal"))]
            custom_proposals: Vec::new(),
        };

        let plaintext = proposals
            .into_iter()
            .map(|p| auth_content_from_proposal(p, sender))
            .collect();

        TestProposals {
            test_sender,
            test_proposals: plaintext,
            expected_effects: effects,
            tree,
        }
    }

    fn filter_proposals(
        cipher_suite: CipherSuite,
        proposals: Vec<AuthenticatedContent>,
    ) -> impl Iterator<Item = (ProposalRef, CachedProposal)> {
        proposals
            .into_iter()
            .filter_map(move |p| match &p.content.content {
                Content::Proposal(proposal) => {
                    let proposal_ref =
                        ProposalRef::from_content(&test_cipher_suite_provider(cipher_suite), &p)
                            .unwrap();
                    Some((
                        proposal_ref,
                        CachedProposal::new(proposal.clone(), p.content.sender),
                    ))
                }
                _ => None,
            })
    }

    fn make_proposal_ref<S>(p: &Proposal, sender: S) -> ProposalRef
    where
        S: Into<Sender>,
    {
        ProposalRef::from_content(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            &auth_content_from_proposal(p.clone(), sender),
        )
        .unwrap()
    }

    fn test_proposal_cache_setup(proposals: Vec<AuthenticatedContent>) -> ProposalCache {
        let mut cache = make_proposal_cache();
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, proposals));
        cache
    }

    fn assert_matches(
        expected_proposals: Vec<ProposalOrRef>,
        expected_effects: ProposalSetEffects,
        proposals: Vec<ProposalOrRef>,
        effects: ProposalSetEffects,
    ) {
        assert_eq!(proposals.len(), expected_proposals.len());

        // Determine there are no duplicates in the proposals returned
        assert!(!proposals.iter().enumerate().any(|(i, p1)| proposals
            .iter()
            .enumerate()
            .any(|(j, p2)| p1 == p2 && i != j)),);

        // Proposal order may change so we just compare the length and contents are the same
        expected_proposals
            .iter()
            .for_each(|p| assert!(proposals.contains(p)));

        assert_eq!(expected_effects, effects);
    }

    #[test]
    async fn test_proposal_cache_commit_all_cached() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    async fn test_proposal_cache_commit_additional() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            mut expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let additional_key_package =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await;

        let additional = vec![Proposal::Add(AddProposal {
            key_package: additional_key_package.clone(),
        })];

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional.clone(),
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        let mut expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        expected_proposals.push(ProposalOrRef::Proposal(additional[0].clone()));

        let leaf = vec![additional_key_package.leaf_node.clone()];

        expected_effects
            .tree
            .add_leaves(leaf, &BasicIdentityProvider)
            .await
            .unwrap();

        expected_effects.adds.push(additional_key_package);
        expected_effects.added_leaf_indexes.push(LeafIndex(3));

        assert_matches(expected_proposals, expected_effects, proposals, effects);
    }

    #[test]
    async fn test_proposal_cache_update_filter() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let additional = vec![Proposal::Update(make_update_proposal("foo").await)];

        let cache = test_proposal_cache_setup(test_proposals);

        let res = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                additional,
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::UPDATE,
                sender: Sender::Member(_),
                by_ref: false,
            })
        );
    }

    #[test]
    async fn test_proposal_cache_removal_override_update() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let update = Proposal::Update(make_update_proposal("foo").await);
        let update_proposal_ref = make_proposal_ref(&update, LeafIndex(1));
        let mut cache = test_proposal_cache_setup(test_proposals);

        cache.insert(update_proposal_ref.clone(), update, Sender::Member(1));

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(effects.removes.contains(&LeafIndex(1)));
        assert!(!proposals.contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[test]
    async fn test_proposal_cache_filter_duplicates_insert() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut cache = test_proposal_cache_setup(test_proposals.clone());
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, test_proposals.clone()));

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    async fn test_proposal_cache_filter_duplicates_additional() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut cache = test_proposal_cache_setup(test_proposals.clone());

        // Updates from different senders will be allowed so we test duplicates for add / remove
        let additional = test_proposals
            .clone()
            .into_iter()
            .filter_map(|plaintext| match plaintext.content.content {
                Content::Proposal(Proposal::Update(_)) => None,
                Content::Proposal(_) => Some(plaintext),
                _ => None,
            })
            .collect::<Vec<_>>();

        cache.extend(filter_proposals(TEST_CIPHER_SUITE, additional));

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(2),
                Vec::new(),
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    async fn test_proposal_cache_is_empty() {
        let mut cache = make_proposal_cache();
        assert!(cache.is_empty());

        let test_proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(test_sender()),
        });

        let proposer = test_sender();
        let test_proposal_ref = make_proposal_ref(&test_proposal, LeafIndex(proposer));
        cache.insert(test_proposal_ref, test_proposal, Sender::Member(proposer));

        assert!(!cache.is_empty())
    }

    #[test]
    async fn test_proposal_cache_resolve() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        })];

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional,
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        let resolution = cache
            .resolve_for_commit_default(
                Sender::Member(test_sender),
                #[cfg(feature = "state_update")]
                Some(LeafIndex(test_sender)),
                proposals,
                None,
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert_eq!(effects, resolution);
    }

    #[test]
    async fn proposal_cache_filters_duplicate_psk_ids() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let proposal = Proposal::Psk(make_external_psk(
            b"ted",
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        ));

        let res = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![proposal.clone(), proposal],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    async fn test_node() -> LeafNode {
        let (mut leaf_node, _, signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo").await;

        leaf_node
            .commit(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_GROUP,
                0,
                default_properties(),
                None,
                &signer,
                ParentHash::empty(),
            )
            .unwrap();

        leaf_node
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn external_commit_must_have_new_leaf() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                vec![ProposalOrRef::Proposal(Proposal::ExternalInit(
                    ExternalInit { kem_output },
                ))],
                None,
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitMustHaveNewLeaf));
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn proposal_cache_rejects_proposals_by_ref_for_new_member() {
        let mut cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let proposal = {
            let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
            Proposal::ExternalInit(ExternalInit { kem_output })
        };

        let proposal_ref = make_proposal_ref(&proposal, test_sender());

        cache.insert(
            proposal_ref.clone(),
            proposal,
            Sender::Member(test_sender()),
        );

        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                vec![ProposalOrRef::Reference(proposal_ref)],
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::OnlyMembersCanCommitProposalsByRef));
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                [
                    Proposal::ExternalInit(ExternalInit {
                        kem_output: kem_output.clone(),
                    }),
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                ]
                .into_iter()
                .map(ProposalOrRef::Proposal)
                .collect(),
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[cfg(feature = "external_commit")]
    async fn new_member_commits_proposal(
        proposal: Proposal,
    ) -> Result<ProposalSetEffects, MlsError> {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                [
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                    proposal,
                ]
                .into_iter()
                .map(ProposalOrRef::Proposal)
                .collect(),
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_cannot_commit_add_proposal() {
        let res = new_member_commits_proposal(Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::ADD
            ))
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_cannot_commit_more_than_one_remove_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let test_leaf_nodes = vec![
            get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
            get_basic_test_node(TEST_CIPHER_SUITE, "bar").await,
        ];

        let test_leaf_node_indexes = public_tree
            .add_leaves(test_leaf_nodes, &BasicIdentityProvider)
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[1],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitWithMoreThanOneRemove));
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_remove_proposal_invalid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "bar").await];

        let test_leaf_node_indexes = public_tree
            .add_leaves(test_leaf_nodes, &BasicIdentityProvider)
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitRemovesOtherIdentity));
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_remove_proposal_valid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "foo").await];

        let test_leaf_node_indexes = public_tree
            .add_leaves(test_leaf_nodes, &BasicIdentityProvider)
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Ok(_));
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_cannot_commit_update_proposal() {
        let res = new_member_commits_proposal(Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
        }))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::UPDATE
            ))
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_cannot_commit_group_extensions_proposal() {
        let res =
            new_member_commits_proposal(Proposal::GroupContextExtensions(ExtensionList::new()))
                .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::GROUP_CONTEXT_EXTENSIONS,
            ))
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_cannot_commit_reinit_proposal() {
        let res = new_member_commits_proposal(Proposal::ReInit(ReInitProposal {
            group_id: b"foo".to_vec(),
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::RE_INIT
            ))
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn new_member_commit_must_contain_an_external_init_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                Vec::new(),
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[test]
    async fn test_path_update_required_empty() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                vec![],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &TreeKemPublic::new(),
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    async fn test_path_update_required_updates() {
        let mut cache = make_proposal_cache();
        let update = Proposal::Update(make_update_proposal("bar").await);
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        cache.insert(
            make_proposal_ref(&update, LeafIndex(2)),
            update,
            Sender::Member(2),
        );

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                Vec::new(),
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &TreeKemPublic::new(),
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    async fn test_path_update_required_removes() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, _) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;
        let alice = 0;

        let (mut tree, _) = TreeKemPublic::derive(alice_leaf, alice_secret, &BasicIdentityProvider)
            .await
            .unwrap();

        let bob = tree
            .add_leaves(
                vec![get_basic_test_node(TEST_CIPHER_SUITE, "bob").await],
                &BasicIdentityProvider,
            )
            .await
            .unwrap()[0];

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(alice),
                vec![remove],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    async fn test_path_update_not_required() {
        let (alice, tree) = new_tree("alice").await;
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let cache = make_proposal_cache();

        let psk = Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId::new(vec![])),
                psk_nonce: PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE))
                    .unwrap(),
            },
        });

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await,
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![psk, add],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[test]
    async fn path_update_is_not_required_for_re_init() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let reinit = Proposal::ReInit(ReInitProposal {
            group_id: vec![],
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: Default::default(),
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![reinit],
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
                &[],
            )
            .await
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[derive(Debug)]
    struct CommitSender<'a, C, F, P, CSP> {
        cipher_suite_provider: CSP,
        tree: &'a TreeKemPublic,
        sender: LeafIndex,
        cache: ProposalCache,
        additional_proposals: Vec<Proposal>,
        identity_provider: C,
        user_rules: F,
        psk_storage: P,
    }

    impl<'a, CSP>
        CommitSender<
            'a,
            BasicWithCustomProvider,
            PassThroughProposalRules,
            AlwaysFoundPskStorage,
            CSP,
        >
    {
        fn new(tree: &'a TreeKemPublic, sender: LeafIndex, cipher_suite_provider: CSP) -> Self {
            Self {
                tree,
                sender,
                cache: make_proposal_cache(),
                additional_proposals: Vec::new(),
                identity_provider: BasicWithCustomProvider::new(BasicIdentityProvider::new()),
                user_rules: pass_through_rules(),
                psk_storage: AlwaysFoundPskStorage,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitSender<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        #[cfg(feature = "external_proposal")]
        fn with_identity_provider<V>(self, identity_provider: V) -> CommitSender<'a, V, F, P, CSP>
        where
            V: IdentityProvider,
        {
            CommitSender {
                identity_provider,
                cipher_suite_provider: self.cipher_suite_provider,
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                user_rules: self.user_rules,
                psk_storage: self.psk_storage,
            }
        }

        fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        fn with_additional<I>(mut self, proposals: I) -> Self
        where
            I: IntoIterator<Item = Proposal>,
        {
            self.additional_proposals.extend(proposals);
            self
        }

        fn with_user_rules<G>(self, f: G) -> CommitSender<'a, C, G, P, CSP>
        where
            G: ProposalRules,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_rules: f,
                psk_storage: self.psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_psk_storage<V>(self, v: V) -> CommitSender<'a, C, F, V, CSP>
        where
            V: PreSharedKeyStorage,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_rules: self.user_rules,
                psk_storage: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        async fn send(&self) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), MlsError> {
            self.cache
                .prepare_commit(
                    Sender::Member(*self.sender),
                    self.additional_proposals.clone(),
                    &ExtensionList::new(),
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    #[cfg(feature = "external_commit")]
                    None,
                    &self.psk_storage,
                    &self.user_rules,
                    &[],
                )
                .await
        }
    }

    async fn key_package_with_invalid_signature() -> KeyPackage {
        let mut kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "mallory").await;
        kp.signature.clear();
        kp
    }

    async fn key_package_with_public_key(key: crypto::HpkePublicKey) -> KeyPackage {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        test_key_package_custom(
            &cipher_suite_provider.clone(),
            TEST_PROTOCOL_VERSION,
            "test",
            |gen| {
                async move {
                    let mut key_package_gen = gen
                        .generate(
                            Lifetime::years(1).unwrap(),
                            Default::default(),
                            Default::default(),
                            Default::default(),
                        )
                        .await
                        .unwrap();

                    key_package_gen.key_package.leaf_node.public_key = key;

                    key_package_gen
                        .key_package
                        .leaf_node
                        .sign(
                            &cipher_suite_provider,
                            gen.signing_key,
                            &LeafNodeSigningContext {
                                group_id: None,
                                leaf_index: None,
                            },
                        )
                        .unwrap();

                    key_package_gen
                        .key_package
                        .sign(&cipher_suite_provider, gen.signing_key, &())
                        .unwrap();
                    key_package_gen
                }
                .boxed()
            },
        )
        .await
    }

    #[test]
    async fn receiving_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        })])
        .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[test]
    async fn sending_additional_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: key_package_with_invalid_signature().await,
            })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[test]
    async fn sending_add_with_invalid_key_package_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn sending_add_with_hpke_key_of_another_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: key_package_with_public_key(
                    tree.get_leaf_node(alice).unwrap().public_key.clone(),
                )
                .await,
            })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(_)));
    }

    #[test]
    async fn sending_add_with_hpke_key_of_another_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(AddProposal {
            key_package: key_package_with_public_key(
                tree.get_leaf_node(alice).unwrap().public_key.clone(),
            )
            .await,
        });

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn receiving_update_with_invalid_leaf_node_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });

        let proposal_ref = make_proposal_ref(&proposal, bob);

        let res = CommitReceiver::new(
            &tree,
            alice,
            bob,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(proposal_ref.clone(), proposal, bob)
        .receive([proposal_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));
    }

    #[test]
    async fn sending_update_with_invalid_leaf_node_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });
        let proposal_ref = make_proposal_ref(&proposal, bob);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref, proposal, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        // Alice didn't propose the update. Bob did. That's why it is not returned in the list of
        // rejected proposals.
        #[cfg(feature = "state_update")]
        assert_eq!(processed_proposals.1.rejected_proposals, Vec::new());
    }

    #[test]
    async fn receiving_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        })])
        .await;

        assert_matches!(res, Err(MlsError::InvalidNodeIndex(20)));
    }

    #[test]
    async fn sending_additional_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(10),
            })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidNodeIndex(20)));
    }

    #[test]
    async fn sending_remove_with_invalid_index_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    fn make_external_psk(id: &[u8], nonce: PskNonce) -> PreSharedKeyProposal {
        PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId::new(id.to_vec())),
                psk_nonce: nonce,
            },
        }
    }

    fn new_external_psk(id: &[u8]) -> PreSharedKeyProposal {
        make_external_psk(
            id,
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        )
    }

    #[test]
    async fn receiving_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Psk(make_external_psk(
            b"foo",
            invalid_nonce.clone(),
        ))])
        .await;

        assert_matches!(
            res,
            Err(
                MlsError::InvalidPskNonceLength { expected, found },
            ) if expected == test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[test]
    async fn sending_additional_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_external_psk(
                b"foo",
                invalid_nonce.clone(),
            ))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(
                MlsError::InvalidPskNonceLength { expected, found },
            ) if expected == test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[test]
    async fn sending_psk_with_invalid_nonce_filters_it_out() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_external_psk(b"foo", invalid_nonce));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    fn make_resumption_psk(usage: ResumptionPSKUsage) -> PreSharedKeyProposal {
        PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage,
                    psk_group_id: PskGroupId(TEST_GROUP.to_vec()),
                    psk_epoch: 1,
                }),
                psk_nonce: PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE))
                    .unwrap(),
            },
        }
    }

    async fn receiving_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Psk(make_resumption_psk(usage))])
        .await;

        assert_matches!(res, Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal));
    }

    async fn sending_additional_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_resumption_psk(usage))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal));
    }

    async fn sending_resumption_psk_with_bad_usage_filters_it_out(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_resumption_psk(usage));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn receiving_resumption_psk_with_reinit_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[test]
    async fn sending_additional_resumption_psk_with_reinit_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[test]
    async fn sending_resumption_psk_with_reinit_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Reinit).await;
    }

    #[test]
    async fn receiving_resumption_psk_with_branch_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[test]
    async fn sending_additional_resumption_psk_with_branch_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[test]
    async fn sending_resumption_psk_with_branch_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Branch).await;
    }

    fn make_reinit(version: ProtocolVersion) -> ReInitProposal {
        ReInitProposal {
            group_id: TEST_GROUP.to_vec(),
            version,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }
    }

    #[test]
    async fn receiving_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::ReInit(make_reinit(smaller_protocol_version))])
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            }) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    #[test]
    async fn sending_additional_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ReInit(make_reinit(smaller_protocol_version))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            }) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    #[test]
    async fn sending_reinit_downgrading_version_filters_it_out() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::ReInit(make_reinit(smaller_protocol_version));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    async fn make_update_proposal(name: &str) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, 1).await,
        }
    }

    async fn make_update_proposal_custom(name: &str, leaf_index: u32) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, leaf_index).await,
        }
    }

    #[test]
    async fn receiving_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;
        let update = Proposal::Update(make_update_proposal("alice").await);
        let update_ref = make_proposal_ref(&update, alice);

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, alice)
        .receive([update_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidCommitSelfUpdate));
    }

    #[test]
    async fn sending_additional_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Update(make_update_proposal("alice").await)])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::UPDATE,
                sender: Sender::Member(_),
                by_ref: false,
            })
        );
    }

    #[test]
    async fn sending_update_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Update(make_update_proposal("alice").await);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn receiving_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Remove(RemoveProposal { to_remove: alice })])
        .await;

        assert_matches!(res, Err(MlsError::CommitterSelfRemoval));
    }

    #[test]
    async fn sending_additional_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal { to_remove: alice })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::CommitterSelfRemoval));
    }

    #[test]
    async fn sending_remove_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Remove(RemoveProposal { to_remove: alice });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn receiving_update_and_remove_for_same_leaf_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, bob);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, bob);

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, bob)
        .cache(remove_ref.clone(), remove, bob)
        .receive([update_ref, remove_ref])
        .await;

        assert_matches!(res, Err(MlsError::UpdatingNonExistingMember));
    }

    #[test]
    async fn sending_updae_and_remove_for_same_leaf_filters_update_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, alice);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref.clone(), update.clone(), alice)
                .cache(remove_ref.clone(), remove, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, vec![remove_ref.into()]);

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(update_ref, update)]
        );
    }

    async fn make_add_proposal() -> AddProposal {
        AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }
    }

    #[cfg(feature = "custom_proposal")]
    async fn make_custom_add_proposal(capabilities: Capabilities) -> AddProposal {
        AddProposal {
            key_package: test_key_package_custom(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_PROTOCOL_VERSION,
                "frank",
                |generator| {
                    async move {
                        generator
                            .generate(
                                Lifetime::years(1).unwrap(),
                                capabilities,
                                ExtensionList::default(),
                                ExtensionList::default(),
                            )
                            .await
                            .unwrap()
                    }
                    .boxed()
                },
            )
            .await,
        }
    }

    #[test]
    async fn receiving_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::Add(make_add_proposal().await),
            Proposal::Add(make_add_proposal().await),
        ])
        .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[test]
    async fn sending_additional_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::Add(make_add_proposal().await),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[test]
    async fn sending_add_proposals_for_same_client_keeps_only_one() {
        let (alice, tree) = new_tree("alice").await;

        let adds = [
            Proposal::Add(make_add_proposal().await),
            Proposal::Add(make_add_proposal().await),
        ];
        let add_refs = adds.clone().map(|p| make_proposal_ref(&p, alice));

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_refs[0].clone(), adds[0].clone(), alice)
                .cache(add_refs[1].clone(), adds[1].clone(), alice)
                .send()
                .await
                .unwrap();

        let committed_add_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(add_ref)] => add_ref,
            _ => panic!("committed proposals list does not contain exactly one reference"),
        };

        assert!(add_refs.contains(committed_add_ref));

        #[cfg(feature = "state_update")]
        assert_matches!(
            &*processed_proposals.1.rejected_proposals,
            [(rejected_add_ref, _)] if committed_add_ref != rejected_add_ref && add_refs.contains(rejected_add_ref)
        );
    }

    #[test]
    async fn receiving_update_for_different_identity_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal_custom("carol", 1).await);
        let update_ref = make_proposal_ref(&update, bob);

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, bob)
        .receive([update_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidSuccessor));
    }

    #[test]
    async fn sending_update_for_different_identity_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("carol").await);
        let update_ref = make_proposal_ref(&update, bob);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref, update, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        // Bob proposed the update, so it is not listed as rejected when Alice commits it because
        // she didn't propose it.
        #[cfg(feature = "state_update")]
        assert_eq!(processed_proposals.1.rejected_proposals, Vec::new());
    }

    #[test]
    async fn receiving_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add])
        .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[test]
    async fn sending_additional_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([add])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[test]
    async fn sending_add_for_same_client_as_existing_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let proposal_ref = make_proposal_ref(&add, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), add.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, add)]
        );
    }

    #[test]
    async fn receiving_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([psk_proposal.clone(), psk_proposal])
        .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[test]
    async fn sending_additional_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([psk_proposal.clone(), psk_proposal])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[test]
    async fn sending_psk_proposals_with_same_psk_id_keeps_only_one() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Psk(new_external_psk(b"foo"));

        let proposal_refs = [
            make_proposal_ref(&proposal, alice),
            make_proposal_ref(&proposal, bob),
        ];

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_refs[0].clone(), proposal.clone(), alice)
                .cache(proposal_refs[1].clone(), proposal, bob)
                .send()
                .await
                .unwrap();

        let committed_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(r)] => r.clone(),
            _ => panic!("Expected single proposal reference in {processed_proposals:?}"),
        };

        assert!(proposal_refs.contains(&committed_ref));

        // The list of rejected proposals may be empty if Bob's proposal was the one that got
        // rejected.
        #[cfg(feature = "state_update")]
        match &*processed_proposals.1.rejected_proposals {
            [(r, _)] => {
                assert_ne!(*r, committed_ref);
                assert!(proposal_refs.contains(r));
            }
            [] => {}
            _ => panic!(
                "Expected zero or one proposal reference in {:?}",
                processed_proposals.1.rejected_proposals
            ),
        }
    }

    #[test]
    async fn receiving_multiple_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::GroupContextExtensions(ExtensionList::new()),
            Proposal::GroupContextExtensions(ExtensionList::new()),
        ])
        .await;

        assert_matches!(
            res,
            Err(MlsError::MoreThanOneGroupContextExtensionsProposal)
        );
    }

    #[test]
    async fn sending_multiple_additional_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::GroupContextExtensions(ExtensionList::new()),
                Proposal::GroupContextExtensions(ExtensionList::new()),
            ])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::MoreThanOneGroupContextExtensionsProposal)
        );
    }

    fn make_extension_list(foo: u8) -> ExtensionList {
        [TestExtension { foo }.into_extension().unwrap()]
            .try_into()
            .unwrap()
    }

    #[test]
    async fn sending_multiple_group_context_extensions_keeps_only_one() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = {
            let (signing_identity, signature_key) =
                get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec());

            let properties = ConfigProperties {
                capabilities: Capabilities {
                    extensions: vec![42.into()],
                    ..Capabilities::default()
                },
                extensions: Default::default(),
            };

            let (leaf, secret) = LeafNode::generate(
                &cipher_suite_provider,
                properties,
                signing_identity,
                &signature_key,
                Lifetime::years(1).unwrap(),
            )
            .await
            .unwrap();

            let (pub_tree, priv_tree) = TreeKemPublic::derive(leaf, secret, &BasicIdentityProvider)
                .await
                .unwrap();

            (priv_tree.self_index, pub_tree)
        };

        let proposals = [
            Proposal::GroupContextExtensions(make_extension_list(0)),
            Proposal::GroupContextExtensions(make_extension_list(1)),
        ];

        let gce_refs = proposals.clone().map(|p| make_proposal_ref(&p, alice));

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(gce_refs[0].clone(), proposals[0].clone(), alice)
                .cache(gce_refs[1].clone(), proposals[1].clone(), alice)
                .send()
                .await
                .unwrap();

        let committed_gce_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(gce_ref)] => gce_ref,
            _ => panic!("committed proposals list does not contain exactly one reference"),
        };

        assert!(gce_refs.contains(committed_gce_ref));

        #[cfg(feature = "state_update")]
        assert_matches!(
            &*processed_proposals.1.rejected_proposals,
            [(rejected_gce_ref, _)] if committed_gce_ref != rejected_gce_ref && gce_refs.contains(rejected_gce_ref)
        );
    }

    #[cfg(feature = "external_proposal")]
    fn make_external_senders_extension() -> ExtensionList {
        [ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec()).0,
        ])
        .into_extension()
        .unwrap()]
        .into()
    }

    #[cfg(feature = "external_proposal")]
    #[test]
    async fn receiving_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_identity_provider(FailureIdentityProvider::new())
        .receive([Proposal::GroupContextExtensions(
            make_external_senders_extension(),
        )])
        .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[cfg(feature = "external_proposal")]
    #[test]
    async fn sending_additional_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_identity_provider(FailureIdentityProvider::new())
            .with_additional([Proposal::GroupContextExtensions(
                make_external_senders_extension(),
            )])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[cfg(feature = "external_proposal")]
    #[test]
    async fn sending_invalid_external_senders_extension_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_external_senders_extension());

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_identity_provider(FailureIdentityProvider::new())
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn receiving_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            Proposal::Add(make_add_proposal().await),
        ])
        .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    #[test]
    async fn sending_additional_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    #[test]
    async fn sending_reinit_with_other_proposals_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let reinit = Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION));
        let reinit_ref = make_proposal_ref(&reinit, alice);
        let add = Proposal::Add(make_add_proposal().await);
        let add_ref = make_proposal_ref(&add, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(reinit_ref.clone(), reinit.clone(), alice)
                .cache(add_ref.clone(), add, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, vec![add_ref.into()]);

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(reinit_ref, reinit)]
        );
    }

    #[cfg(feature = "external_commit")]
    fn make_external_init() -> ExternalInit {
        ExternalInit {
            kem_output: vec![33; test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size()],
        }
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn receiving_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::ExternalInit(make_external_init())])
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::EXTERNAL_INIT,
                sender: Sender::Member(_),
                by_ref: false,
            })
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn sending_additional_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ExternalInit(make_external_init())])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::EXTERNAL_INIT,
                sender: Sender::Member(_),
                by_ref: false,
            })
        );
    }

    #[cfg(feature = "external_commit")]
    #[test]
    async fn sending_external_init_from_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let external_init = Proposal::ExternalInit(make_external_init());
        let external_init_ref = make_proposal_ref(&external_init, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(external_init_ref.clone(), external_init.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(external_init_ref, external_init)]
        );
    }

    fn required_capabilities_proposal(extension: u16) -> Proposal {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![extension.into()],
            ..Default::default()
        };

        Proposal::GroupContextExtensions(Into::<ExtensionList>::into([required_capabilities
            .into_extension()
            .unwrap()]))
    }

    #[test]
    async fn receiving_required_capabilities_not_supported_by_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([required_capabilities_proposal(33)])
        .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredExtensionNotFound(v)) if v == 33.into()
        );
    }

    #[test]
    async fn sending_required_capabilities_not_supported_by_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([required_capabilities_proposal(33)])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredExtensionNotFound(v)) if v == 33.into()
        );
    }

    #[test]
    async fn sending_additional_required_capabilities_not_supported_by_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = required_capabilities_proposal(33);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn committing_update_from_pk1_to_pk2_and_update_from_pk2_to_pk3_works() {
        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(alice_leaf.clone(), alice_secret, &BasicIdentityProvider)
                .await
                .unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob").await;
        let carol = add_member(&mut tree, "carol").await;

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };

        alice_new_leaf
            .sign(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                &alice_signer,
                &(TEST_GROUP, 0).into(),
            )
            .unwrap();

        let bob_new_leaf = update_leaf_node("bob", 1).await;

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let pk2_to_pk3 = Proposal::Update(UpdateProposal {
            leaf_node: bob_new_leaf.clone(),
        });

        let pk2_to_pk3_ref = make_proposal_ref(&pk2_to_pk3, bob);

        let effects = CommitReceiver::new(
            &tree,
            carol,
            carol,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
        .cache(pk2_to_pk3_ref.clone(), pk2_to_pk3, bob)
        .receive([pk1_to_pk2_ref, pk2_to_pk3_ref])
        .await
        .unwrap();

        assert_eq!(
            effects.updates,
            vec![(alice, alice_new_leaf), (bob, bob_new_leaf)]
        );
    }

    #[test]
    async fn committing_update_from_pk1_to_pk2_and_removal_of_pk2_works() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(alice_leaf.clone(), alice_secret, &BasicIdentityProvider)
                .await
                .unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob").await;
        let carol = add_member(&mut tree, "carol").await;

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };

        alice_new_leaf
            .sign(
                &cipher_suite_provider,
                &alice_signer,
                &(TEST_GROUP, 0).into(),
            )
            .unwrap();

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let remove_pk2 = Proposal::Remove(RemoveProposal { to_remove: bob });

        let remove_pk2_ref = make_proposal_ref(&remove_pk2, bob);

        let effects = CommitReceiver::new(
            &tree,
            carol,
            carol,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
        .cache(remove_pk2_ref.clone(), remove_pk2, bob)
        .receive([pk1_to_pk2_ref, remove_pk2_ref])
        .await
        .unwrap();

        assert_eq!(effects.updates, vec![(alice, alice_new_leaf)]);
        assert_eq!(effects.removes, vec![bob]);
    }

    async fn unsupported_credential_key_package(name: &str) -> KeyPackage {
        let (mut signing_identity, secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, name.as_bytes().to_vec());

        signing_identity.credential = Credential::Custom(CustomCredential::new(
            CredentialType::new(BasicWithCustomProvider::CUSTOM_CREDENTIAL_TYPE),
            random_bytes(32),
        ));

        let generator = KeyPackageGenerator {
            protocol_version: TEST_PROTOCOL_VERSION,
            cipher_suite_provider: &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            signing_identity: &signing_identity,
            signing_key: &secret_key,
            identity_provider: &BasicWithCustomProvider::new(BasicIdentityProvider::new()),
        };

        generator
            .generate(
                Lifetime::years(1).unwrap(),
                Capabilities {
                    credentials: vec![42.into()],
                    ..Default::default()
                },
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap()
            .key_package
    }

    #[test]
    async fn receiving_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        })])
        .await;

        assert_matches!(
            res,
            Err(MlsError::InUseCredentialTypeUnsupportedByNewLeaf(c, _)) if c == BasicCredential::credential_type()
        );
    }

    #[test]
    async fn sending_additional_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: unsupported_credential_key_package("bob").await,
            })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::InUseCredentialTypeUnsupportedByNewLeaf(c,_)
            ) if c == BasicCredential::credential_type()
        );
    }

    #[test]
    async fn sending_add_with_leaf_not_supporting_credential_type_of_other_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let add = Proposal::Add(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        });

        let add_ref = make_proposal_ref(&add, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_ref.clone(), add.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(add_ref, add)]
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn sending_custom_proposal_with_member_not_supporting_proposal_type_fails() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([custom_proposal.clone()])
            .send()
            .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedCustomProposal(c)
            ) if c == custom_proposal.proposal_type()
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn sending_custom_proposal_with_member_not_supporting_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let custom_ref = make_proposal_ref(&custom_proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(custom_ref.clone(), custom_proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(custom_ref, custom_proposal)]
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn receiving_custom_proposal_with_member_not_supporting_fails() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([custom_proposal.clone()])
        .await;

        assert_matches!(
            res,
            Err(MlsError::UnsupportedCustomProposal(c)) if c == custom_proposal.proposal_type()
        );
    }

    #[test]
    async fn receiving_group_extension_unsupported_by_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::GroupContextExtensions(make_extension_list(0))])
        .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedGroupExtension(v)
            ) if v == 42.into()
        );
    }

    #[test]
    async fn sending_additional_group_extension_unsupported_by_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(make_extension_list(0))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedGroupExtension(v)
            ) if v == 42.into()
        );
    }

    #[test]
    async fn sending_group_extension_unsupported_by_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_extension_list(0));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[derive(Debug)]
    struct AlwaysNotFoundPskStorage;

    #[async_trait]
    impl PreSharedKeyStorage for AlwaysNotFoundPskStorage {
        type Error = Infallible;

        async fn get(&self, _: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
            Ok(None)
        }
    }

    #[test]
    async fn receiving_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_psk_storage(AlwaysNotFoundPskStorage)
        .receive([Proposal::Psk(new_external_psk(b"abc"))])
        .await;

        assert_matches!(res, Err(MlsError::NoPskForId(_)));
    }

    #[test]
    async fn sending_additional_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_psk_storage(AlwaysNotFoundPskStorage)
            .with_additional([Proposal::Psk(new_external_psk(b"abc"))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::NoPskForId(_)));
    }

    #[test]
    async fn sending_external_psk_with_unknown_id_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(new_external_psk(b"abc"));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_psk_storage(AlwaysNotFoundPskStorage)
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[test]
    async fn user_defined_filter_can_remove_proposals() {
        struct RemoveGroupContextExtensions;

        #[async_trait]
        impl ProposalRules for RemoveGroupContextExtensions {
            type Error = Infallible;

            #[cfg(feature = "custom_proposal")]
            async fn expand_custom_proposals(
                &self,
                _current_roster: &[Member],
                _extension_list: &ExtensionList,
                _proposals: &[ProposalInfo<CustomProposal>],
            ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
                Ok(vec![])
            }

            async fn validate(
                &self,
                _: Sender,
                _: &[Member],
                _: &ExtensionList,
                _: &ProposalBundle,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            async fn filter(
                &self,
                _: Sender,
                _: &[Member],
                _: &ExtensionList,
                mut proposals: ProposalBundle,
            ) -> Result<ProposalBundle, Self::Error> {
                proposals.clear_group_context_extensions();
                Ok(proposals)
            }
        }

        let (alice, tree) = new_tree("alice").await;

        let (committed, _) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_additional([Proposal::GroupContextExtensions(Default::default())])
                .with_user_rules(RemoveGroupContextExtensions)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
    }

    struct FailureProposalRules;

    #[async_trait]
    impl ProposalRules for FailureProposalRules {
        type Error = MlsError;

        #[cfg(feature = "custom_proposal")]
        async fn expand_custom_proposals(
            &self,
            _current_roster: &[Member],
            _extension_list: &ExtensionList,
            _proposals: &[ProposalInfo<CustomProposal>],
        ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
            Ok(vec![])
        }

        async fn validate(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: &ProposalBundle,
        ) -> Result<(), Self::Error> {
            Err(MlsError::InvalidSignature)
        }

        async fn filter(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: ProposalBundle,
        ) -> Result<ProposalBundle, Self::Error> {
            Err(MlsError::InvalidSignature)
        }
    }

    #[test]
    async fn user_defined_filter_can_refuse_to_send_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(Default::default())])
            .with_user_rules(FailureProposalRules)
            .send()
            .await;

        assert_matches!(res, Err(MlsError::UserDefinedProposalFilterError(_)));
    }

    #[test]
    async fn user_defined_filter_can_reject_incoming_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(FailureProposalRules)
        .receive([Proposal::GroupContextExtensions(Default::default())])
        .await;

        assert_matches!(res, Err(MlsError::UserDefinedProposalFilterError(_)));
    }

    #[cfg(feature = "custom_proposal")]
    #[derive(Debug, Clone)]
    struct ExpandCustomRules {
        to_expand: Vec<ProposalInfo<Proposal>>,
    }

    #[cfg(feature = "custom_proposal")]
    #[async_trait]
    impl ProposalRules for ExpandCustomRules {
        type Error = Infallible;

        async fn expand_custom_proposals(
            &self,
            _current_roster: &[Member],
            _extension_list: &ExtensionList,
            _proposals: &[ProposalInfo<CustomProposal>],
        ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
            Ok(self.to_expand.clone())
        }

        async fn validate(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: &ProposalBundle,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn filter(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            bundle: ProposalBundle,
        ) -> Result<ProposalBundle, Self::Error> {
            Ok(bundle)
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn user_defined_custom_proposal_rules_are_applied_on_send() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let add_proposal = make_custom_add_proposal(Capabilities {
            proposals: vec![ProposalType::new(42)],
            ..get_test_capabilities()
        })
        .await;

        let expander = ExpandCustomRules {
            to_expand: vec![ProposalInfo {
                proposal: Proposal::Add(add_proposal.clone()),
                sender: Sender::Member(alice.into()),
                source: ProposalSource::CustomRule(true),
            }],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_user_rules(expander.clone())
                .with_additional(vec![Proposal::Custom(custom_proposal.clone())])
                .send()
                .await
                .unwrap();

        assert_eq!(
            processed_proposals.0,
            vec![ProposalOrRef::Proposal(Proposal::Custom(
                custom_proposal.clone()
            ))]
        );

        #[cfg(feature = "state_update")]
        assert_eq!(processed_proposals.1.adds, vec![add_proposal.key_package]);

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.custom_proposals,
            vec![custom_proposal]
        )
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn user_defined_custom_proposal_rules_are_applied_on_receive() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let add_proposal = make_custom_add_proposal(Capabilities {
            proposals: vec![ProposalType::new(42)],
            ..get_test_capabilities()
        })
        .await;

        let expander = ExpandCustomRules {
            to_expand: vec![ProposalInfo {
                proposal: Proposal::Add(add_proposal.clone()),
                sender: Sender::Member(0),
                source: ProposalSource::CustomRule(true),
            }],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let effects = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(expander.clone())
        .receive(vec![Proposal::Custom(custom_proposal.clone())])
        .await
        .unwrap();

        // If the add is applied, then the custom proposal must have been applied.
        assert_eq!(effects.adds, vec![add_proposal.key_package]);

        // Check that `custom_proposals` are computed correctly.
        #[cfg(feature = "state_update")]
        assert_eq!(effects.custom_proposals, vec![custom_proposal])
    }

    #[cfg(feature = "custom_proposal")]
    #[test]
    async fn user_defined_custom_proposal_rules_are_not_exempt_from_base_rules() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let expander = ExpandCustomRules {
            to_expand: vec![ProposalInfo {
                proposal: Proposal::Update(UpdateProposal {
                    leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "leaf").await,
                }),
                sender: Sender::NewMemberCommit,
                source: ProposalSource::CustomRule(true),
            }],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(expander.clone())
        .receive(vec![Proposal::Custom(custom_proposal.clone())])
        .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender { .. }))
    }

    #[test]
    async fn proposers_are_verified() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        #[cfg(feature = "external_proposal")]
        let external_senders = ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"carol".to_vec()).0,
        ]);

        let sender_is_valid = |sender: &Sender| match sender {
            Sender::Member(i) => tree.get_leaf_node(LeafIndex(*i)).is_ok(),
            #[cfg(feature = "external_proposal")]
            Sender::External(i) => (*i as usize) < external_senders.allowed_senders.len(),
            _ => true,
        };

        let proposals: &[Proposal] = &[
            Proposal::Add(make_add_proposal().await),
            Proposal::Update(make_update_proposal("alice").await),
            Proposal::Remove(RemoveProposal { to_remove: bob }),
            Proposal::Psk(make_external_psk(
                b"ted",
                PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
            )),
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            #[cfg(feature = "external_commit")]
            Proposal::ExternalInit(make_external_init()),
            Proposal::GroupContextExtensions(Default::default()),
        ];

        let proposers = [
            Sender::Member(*alice),
            Sender::Member(33),
            #[cfg(feature = "external_proposal")]
            Sender::External(0),
            #[cfg(feature = "external_proposal")]
            Sender::External(1),
            #[cfg(feature = "external_commit")]
            Sender::NewMemberCommit,
            Sender::NewMemberProposal,
        ];

        for ((proposer, proposal), by_ref) in proposers
            .into_iter()
            .cartesian_product(proposals)
            .cartesian_product([false, true])
        {
            let committer = Sender::Member(*alice);

            let receiver = CommitReceiver::new(
                &tree,
                committer,
                alice,
                test_cipher_suite_provider(TEST_CIPHER_SUITE),
            );

            #[cfg(feature = "external_proposal")]
            let extensions: ExtensionList =
                [external_senders.clone().into_extension().unwrap()].into();

            #[cfg(feature = "external_proposal")]
            let receiver = receiver.with_extensions(extensions);

            let (receiver, proposals, proposer) = if by_ref {
                let proposal_ref = make_proposal_ref(proposal, proposer);
                let receiver = receiver.cache(proposal_ref.clone(), proposal.clone(), proposer);
                (receiver, vec![ProposalOrRef::from(proposal_ref)], proposer)
            } else {
                (receiver, vec![proposal.clone().into()], committer)
            };

            let res = receiver.receive(proposals).await;

            if !proposer_can_propose(&proposer, proposal.proposal_type(), by_ref) {
                assert_matches!(
                    res,
                    Err(
                        MlsError::InvalidProposalTypeForSender {
                            proposal_type: found_type,
                            sender: found_sender,
                            by_ref: found_by_ref,
                        }
                    ) if found_type == proposal.proposal_type() && found_sender == proposer && found_by_ref == by_ref
                );
            } else if !sender_is_valid(&proposer) {
                match proposer {
                    Sender::Member(i) => assert_matches!(
                        res,
                        Err(
                            MlsError::InvalidMemberProposer(index)
                        ) if i == index
                    ),
                    #[cfg(feature = "external_proposal")]
                    Sender::External(i) => assert_matches!(
                        res,
                        Err(
                            MlsError::InvalidExternalSenderIndex(index)
                        ) if i == index
                    ),
                    _ => unreachable!(),
                }
            } else {
                let is_self_update = proposal.proposal_type() == ProposalType::UPDATE
                    && by_ref
                    && matches!(proposer, Sender::Member(_));

                if !is_self_update {
                    res.unwrap();
                }
            }
        }
    }
}
