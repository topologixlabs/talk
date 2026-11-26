//! Talk local prototype. Message encryption is done by OpenMLS and libcrux, the
//! connection by rustls, and key stretching by Argon2. This crate only calls them.

pub mod pki;
pub mod relay;
pub mod sync;
pub mod vault;

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use openmls_traits::{crypto::OpenMlsCrypto, types::HashType, OpenMlsProvider};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Hybrid X-Wing (X25519 + ML-KEM-768) key exchange. Signatures are classical Ed25519.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
pub const MAX_HELD: usize = 256;
pub const MAX_REINVITES: u8 = 3;

pub type Res<T> = Result<T, String>;

pub(crate) fn err<E: std::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Text { sender: String, text: String },
    GroupChanged { still_member: bool },
}

pub struct Client {
    pub name: String,
    provider: Provider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
    /// People verified in person: name -> signing key.
    contacts: BTreeMap<String, Vec<u8>>,
    held: VecDeque<Vec<u8>>,
    reinvites_used: BTreeSet<Vec<u8>>,
    reinvite_counts: BTreeMap<String, u8>,
}

fn capabilities() -> Capabilities {
    Capabilities::new(None, Some(&[SUITE]), None, None, Some(&[CredentialType::Basic]))
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn identity(c: &Credential) -> String {
    BasicCredential::try_from(c.clone())
        .map(|b| String::from_utf8_lossy(b.identity()).into_owned())
        .unwrap_or_else(|_| "<unknown>".into())
}

fn encode(m: &MlsMessageOut) -> Res<Vec<u8>> {
    m.tls_serialize_detached().map_err(err)
}

fn card_bytes(name: &str, key: &[u8]) -> Vec<u8> {
    let mut v = (name.len() as u16).to_be_bytes().to_vec();
    v.extend(name.as_bytes());
    v.extend((key.len() as u16).to_be_bytes());
    v.extend(key);
    v
}

fn parse_card(card: &[u8]) -> Res<(String, Vec<u8>)> {
    let bad = || "invalid identity card".to_string();
    let n = u16::from_be_bytes(card.get(..2).ok_or_else(bad)?.try_into().map_err(err)?) as usize;
    let name = String::from_utf8(card.get(2..2 + n).ok_or_else(bad)?.to_vec()).map_err(err)?;
    let k = u16::from_be_bytes(card.get(2 + n..4 + n).ok_or_else(bad)?.try_into().map_err(err)?) as usize;
    let key = card.get(4 + n..4 + n + k).ok_or_else(bad)?.to_vec();
    if card.len() != 4 + n + k || name.is_empty() || key.len() != 32 {
        return Err(bad());
    }
    Ok((name, key))
}

/// Checks a group member's name and key against the verified contact list.
fn check_person(
    contacts: &BTreeMap<String, Vec<u8>>,
    me: &str,
    my_key: &[u8],
    credential: &Credential,
    key: &[u8],
) -> Res<()> {
    let who = identity(credential);
    let verified = if who == me { key == my_key } else { contacts.get(&who).is_some_and(|k| k == key) };
    if verified { Ok(()) } else { Err(format!("unverified identity: {who}")) }
}

impl Client {
    pub(crate) fn empty(name: &str, provider: Provider, signer: Option<SignatureKeyPair>) -> Res<Self> {
        if name.is_empty() || name.len() > 32 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("invalid name".into());
        }
        let signer = match signer {
            Some(s) => s,
            None => SignatureKeyPair::new(SUITE.signature_algorithm()).map_err(err)?,
        };
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            name: name.into(),
            provider,
            signer,
            credential,
            group: None,
            contacts: BTreeMap::new(),
            held: VecDeque::new(),
            reinvites_used: BTreeSet::new(),
            reinvite_counts: BTreeMap::new(),
        })
    }

    pub fn new(name: &str) -> Res<Self> {
        let c = Self::empty(name, Provider::new().map_err(err)?, None)?;
        c.signer.store(c.provider.storage()).map_err(err)?;
        Ok(c)
    }

    /// A separate group state for one chat, sharing this person's identity and contacts.
    pub fn for_chat(&self) -> Res<Self> {
        let signer = SignatureKeyPair::read(self.provider.storage(), self.signer.public(), self.signer.signature_scheme())
            .ok_or("signing key missing")?;
        let mut c = Self::empty(&self.name, Provider::new().map_err(err)?, Some(signer))?;
        c.signer.store(c.provider.storage()).map_err(err)?;
        c.contacts = self.contacts.clone();
        Ok(c)
    }

    pub fn copy_contacts_from(&mut self, other: &Client) {
        self.contacts = other.contacts.clone();
    }

    pub fn is_verified(&self, name: &str) -> bool {
        self.contacts.contains_key(name)
    }

    pub fn member_names(&self) -> Vec<String> {
        self.group.as_ref().map_or_else(Vec::new, |g| g.members().map(|m| identity(&m.credential)).collect())
    }

    // ---------- Identity ----------

    /// Public name and key, to hand over in person or by QR code.
    pub fn identity_card(&self) -> Vec<u8> {
        card_bytes(&self.name, self.signer.public())
    }

    /// A code both people compare. It matches only if each holds the other's real key.
    pub fn safety_code(&self, their_card: &[u8]) -> Res<String> {
        let (name, key) = parse_card(their_card)?;
        let mut ids = [self.identity_card(), card_bytes(&name, &key)];
        ids.sort();
        let mut input = b"talk-safety-code-v1".to_vec();
        input.extend(&ids[0]);
        input.extend(&ids[1]);
        let hash = self.provider.crypto().hash(HashType::Sha2_256, &input).map_err(err)?;
        let groups: Vec<String> = hash
            .chunks_exact(4)
            .map(|c| format!("{:05}", u32::from_be_bytes(c.try_into().unwrap()) % 100_000))
            .collect();
        Ok(groups.join(" "))
    }

    /// Trusts a card only if the code the other person read out matches.
    pub fn trust_contact(&mut self, their_card: &[u8], code_they_read: &str) -> Res<()> {
        let (name, key) = parse_card(their_card)?;
        if name == self.name {
            return Err("cannot verify yourself".into());
        }
        if self.safety_code(their_card)? != code_they_read.trim() {
            return Err("safety codes do not match".into());
        }
        if self.contacts.get(&name).is_some_and(|k| *k != key) {
            return Err("this person's key has changed; verify again".into());
        }
        self.contacts.insert(name, key);
        Ok(())
    }

    /// Removes a contact, so a changed key can be deliberately re-verified.
    pub fn forget_contact(&mut self, name: &str) {
        self.contacts.remove(name);
    }

    fn checked_package(&self, key_package: &[u8]) -> Res<KeyPackage> {
        let message = MlsMessageIn::tls_deserialize_exact(key_package).map_err(err)?;
        let MlsMessageBodyIn::KeyPackage(incoming) = message.extract() else {
            return Err("not a key package".into());
        };
        let package = incoming
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(err)?;
        if package.ciphersuite() != SUITE {
            return Err("key package does not use the required hybrid suite".into());
        }
        let leaf = package.leaf_node();
        check_person(&self.contacts, &self.name, self.signer.public(), leaf.credential(), leaf.signature_key().as_slice())?;
        Ok(package)
    }

    // ---------- Group ----------

    /// A one-time public package that lets someone add this client to a group.
    pub fn key_package(&self) -> Res<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(err)?;
        encode(&MlsMessageOut::from(bundle.key_package().clone()))
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Res<()> {
        if group_id.is_empty() || group_id.len() > 24 {
            return Err("group ID must be 1 to 24 bytes".into());
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .capabilities(capabilities())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(err)?;
        self.group = Some(group);
        Ok(())
    }

    fn group_ref(&self) -> Res<&MlsGroup> {
        self.group.as_ref().ok_or_else(|| "not in a group".to_string())
    }

    /// The relay's ordered log name for this group.
    pub fn log_name(&self) -> Res<String> {
        let id = self.group_ref()?.group_id().as_slice();
        Ok(format!("log/{}", id.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }

    /// Prepares an add without applying it. Returns (commit, welcome).
    pub fn begin_add(&mut self, key_package: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
        let package = self.checked_package(key_package)?;
        let Self { provider, signer, group, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        let (commit, welcome, _) = group.add_members(provider, signer, &[package]).map_err(err)?;
        Ok((encode(&commit)?, encode(&welcome)?))
    }

    pub fn begin_remove(&mut self, name: &str) -> Res<Vec<u8>> {
        let index = self.member_index(name)?;
        let Self { provider, signer, group, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        let (commit, _, _) = group.remove_members(provider, signer, &[index]).map_err(err)?;
        encode(&commit)
    }

    pub fn begin_update(&mut self) -> Res<Vec<u8>> {
        let Self { provider, signer, group, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        let bundle = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(err)?;
        let (commit, _, _) = bundle.into_contents();
        encode(&commit)
    }

    fn member_index(&self, name: &str) -> Res<LeafNodeIndex> {
        self.group_ref()?
            .members()
            .find(|m| identity(&m.credential) == name)
            .map(|m| m.index)
            .ok_or_else(|| "no such member".to_string())
    }

    /// Checks a re-invite request once. Returns the person's name if it is acceptable.
    pub fn accept_reinvite(&mut self, key_package: &[u8]) -> Res<String> {
        let package = self.checked_package(key_package)?;
        let name = identity(package.leaf_node().credential());
        self.member_index(&name)?;
        let digest = self.provider.crypto().hash(HashType::Sha2_256, key_package).map_err(err)?;
        if self.reinvites_used.contains(&digest) {
            return Err("re-invite request already used".into());
        }
        let count = self.reinvite_counts.get(&name).copied().unwrap_or(0);
        if count >= MAX_REINVITES {
            return Err("too many re-invite requests".into());
        }
        self.reinvites_used.insert(digest);
        self.reinvite_counts.insert(name.clone(), count + 1);
        Ok(name)
    }

    /// Replaces a person's failed membership with a fresh package, in one commit.
    pub fn begin_swap(&mut self, name: &str, key_package: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
        let package = self.checked_package(key_package)?;
        if identity(package.leaf_node().credential()) != name {
            return Err("package does not belong to this person".into());
        }
        let index = self.member_index(name)?;
        let Self { provider, signer, group, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        let out = group
            .swap_members(provider, signer, &[index], &[package])
            .map_err(err)?;
        Ok((encode(&out.commit)?, encode(&out.welcome)?))
    }

    pub fn confirm_commit(&mut self) -> Res<()> {
        let Self { provider, group, .. } = self;
        group.as_mut().ok_or("not in a group")?.merge_pending_commit(provider).map_err(err)
    }

    pub fn abort_commit(&mut self) -> Res<()> {
        let Self { provider, group, .. } = self;
        group
            .as_mut()
            .ok_or("not in a group")?
            .clear_pending_commit(provider.storage())
            .map_err(err)
    }

    /// Returns (commit for existing members, welcome for the new member).
    pub fn add_member(&mut self, key_package: &[u8]) -> Res<(Vec<u8>, Vec<u8>)> {
        let out = self.begin_add(key_package)?;
        self.confirm_commit()?;
        Ok(out)
    }

    pub fn remove_member(&mut self, name: &str) -> Res<Vec<u8>> {
        let out = self.begin_remove(name)?;
        self.confirm_commit()?;
        Ok(out)
    }

    /// Replaces this member's encryption keys and moves the group to a new epoch.
    pub fn update_keys(&mut self) -> Res<Vec<u8>> {
        let out = self.begin_update()?;
        self.confirm_commit()?;
        Ok(out)
    }

    pub fn join(&mut self, welcome: &[u8]) -> Res<()> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(err)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err("not a welcome".into());
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(err)?;
        for m in staged.members() {
            check_person(&self.contacts, &self.name, self.signer.public(), &m.credential, &m.signature_key)?;
        }
        let group = staged.into_group(&self.provider).map_err(err)?;
        if group.ciphersuite() != SUITE {
            return Err("group does not use the required hybrid suite".into());
        }
        self.group = Some(group);
        Ok(())
    }

    pub fn send(&mut self, text: &str) -> Res<Vec<u8>> {
        let Self { provider, signer, group, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        encode(&group.create_message(provider, signer, text.as_bytes()).map_err(err)?)
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Res<Event> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(err)?;
        // Plaintext-framed messages are refused: only encrypted framing is accepted.
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            return Err("only encrypted group messages are accepted".into());
        };
        let my_key = self.signer.public().to_vec();
        let Self { provider, group, contacts, name, .. } = self;
        let group = group.as_mut().ok_or("not in a group")?;
        let processed = group
            .process_message(provider, ProtocolMessage::from(private))
            .map_err(err)?;
        let sender = identity(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let text = String::from_utf8(app.into_bytes()).map_err(err)?;
                Ok(Event::Text { sender, text })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                for add in commit.add_proposals() {
                    let leaf = add.add_proposal().key_package().leaf_node();
                    check_person(contacts, name, &my_key, leaf.credential(), leaf.signature_key().as_slice())?;
                }
                for update in commit.update_proposals() {
                    let leaf = update.update_proposal().leaf_node();
                    check_person(contacts, name, &my_key, leaf.credential(), leaf.signature_key().as_slice())?;
                }
                if let Some(leaf) = commit.update_path_leaf_node() {
                    check_person(contacts, name, &my_key, leaf.credential(), leaf.signature_key().as_slice())?;
                }
                group.merge_staged_commit(provider, *commit).map_err(err)?;
                Ok(Event::GroupChanged { still_member: group.is_active() })
            }
            _ => Err("unsupported message type".into()),
        }
    }

    /// The group a sealed message belongs to, used only for local routing.
    pub fn message_group(bytes: &[u8]) -> Res<Vec<u8>> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(err)?;
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            return Err("only encrypted group messages are accepted".into());
        };
        Ok(ProtocolMessage::from(private).group_id().as_slice().to_vec())
    }

    pub fn message_epoch(bytes: &[u8]) -> Res<u64> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(err)?;
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            return Err("only encrypted group messages are accepted".into());
        };
        Ok(ProtocolMessage::from(private).epoch().as_u64())
    }

    /// Applies a group change. Anything that is not a valid commit is refused
    /// without consuming a message key.
    pub fn apply_commit(&mut self, bytes: &[u8]) -> Res<()> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(err)?;
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            return Err("only encrypted group messages are accepted".into());
        };
        if ProtocolMessage::from(private).content_type() != ContentType::Commit {
            return Err("not a group change".into());
        }
        match self.receive(bytes)? {
            Event::GroupChanged { .. } => Ok(()),
            _ => Err("not a group change".into()),
        }
    }

    /// Holds a message from a future epoch until the matching group change arrives.
    pub fn receive_or_hold(&mut self, bytes: &[u8]) -> Res<Option<Event>> {
        if Self::message_epoch(bytes)? > self.epoch()? {
            if self.held.len() >= MAX_HELD {
                return Err("too many held messages".into());
            }
            self.held.push_back(bytes.to_vec());
            return Ok(None);
        }
        self.receive(bytes).map(Some)
    }

    /// Delivers held messages that are now readable. Undecryptable ones are dropped.
    pub fn drain_held(&mut self) -> Vec<Event> {
        let Ok(epoch) = self.epoch() else { return Vec::new() };
        let mut events = Vec::new();
        for bytes in std::mem::take(&mut self.held) {
            match Self::message_epoch(&bytes) {
                Ok(e) if e > epoch => self.held.push_back(bytes),
                Ok(_) => {
                    if let Ok(event) = self.receive(&bytes) {
                        events.push(event);
                    }
                }
                Err(_) => {}
            }
        }
        events
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// A value all members of the same epoch share; used in tests to compare keys.
    pub fn export_secret(&self) -> Res<Vec<u8>> {
        self.group_ref()?
            .export_secret(self.provider.crypto(), "talk prototype test", b"", 32)
            .map_err(err)
    }

    /// Members compare this to detect a relay showing them different group histories.
    pub fn group_check_code(&self) -> Res<Vec<u8>> {
        Ok(self.group_ref()?.epoch_authenticator().as_slice().to_vec())
    }

    pub fn epoch(&self) -> Res<u64> {
        Ok(self.group_ref()?.epoch().as_u64())
    }

    pub fn is_active(&self) -> bool {
        self.group.as_ref().is_some_and(|g| g.is_active())
    }

    pub fn group_suite(&self) -> Res<u16> {
        Ok(u16::from(self.group_ref()?.ciphersuite()))
    }
}

/// Simulates two people meeting and comparing safety codes correctly.
pub fn meet_in_person(a: &mut Client, b: &mut Client) -> Res<()> {
    let (card_a, card_b) = (a.identity_card(), b.identity_card());
    let (code_a, code_b) = (a.safety_code(&card_b)?, b.safety_code(&card_a)?);
    a.trust_contact(&card_b, &code_b)?;
    b.trust_contact(&card_a, &code_a)
}

/// Length of the public init key in a key package. X-Wing is 1,216 bytes.
pub fn init_key_len(key_package: &[u8]) -> Res<usize> {
    let provider = Provider::new().map_err(err)?;
    let message = MlsMessageIn::tls_deserialize_exact(key_package).map_err(err)?;
    let MlsMessageBodyIn::KeyPackage(incoming) = message.extract() else {
        return Err("not a key package".into());
    };
    let package = incoming
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(err)?;
    Ok(package.hpke_init_key().as_slice().len())
}

pub fn validate_key_package(key_package: &[u8]) -> Res<()> {
    init_key_len(key_package).map(|_| ())
}
