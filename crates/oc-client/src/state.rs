//! Serialized client state.
//!
//! This structure is never written to disk in plaintext: [`crate::StateStore`]
//! encrypts it with XChaCha20-Poly1305 before touching the filesystem.

use std::collections::VecDeque;

use oc_core::identity::{Identity, PublicIdentity, safety_number};
use oc_core::ratchet::RatchetSnapshot;
use oc_core::x3dh::{PREKEY_PAIR_LEN, PrekeyBundle, PrekeyPair};
use oc_core::{now_unix, random_array};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Current state format version.
pub const STATE_VERSION: u32 = 1;
/// Serialized private identity length.
pub const IDENTITY_LEN: usize = 64;
/// Maximum number of remembered message ids.
pub const SEEN_CAPACITY: usize = 4096;
/// Maximum number of queued outgoing messages.
pub const OUTBOX_CAPACITY: usize = 1024;
/// Maximum number of remembered delivery acknowledgements.
pub const ACK_CAPACITY: usize = 4096;

/// One outgoing event waiting to be accepted by a relay.
///
/// The payload is already ratchet-encrypted and sealed to a mailbox, so a
/// retry republishes exactly the same bytes and never advances the ratchet.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutboxRecord {
    /// Message id of the application body inside the envelope.
    pub msg_id: [u8; 16],
    /// Conversation partner.
    pub peer_id: [u8; 32],
    /// Mailbox the sealed payload is addressed to.
    pub mailbox: [u8; 32],
    /// Sealed envelope bytes, opaque to the relay.
    pub payload: Vec<u8>,
    /// UNIX seconds when the event was created.
    pub created_at: u64,
    /// UNIX seconds after which the event may be dropped.
    pub expires_at: u64,
    /// Number of publish attempts so far.
    #[serde(default)]
    pub attempts: u32,
    /// UNIX seconds before which the next automatic retry should wait.
    #[serde(default)]
    pub next_attempt_at: u64,
}

impl core::fmt::Debug for OutboxRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboxRecord")
            .field("msg_id", &hex::encode(self.msg_id))
            .field("peer_id", &hex::encode(self.peer_id))
            .field("created_at", &self.created_at)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// One conversation partner.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContactRecord {
    /// Self-certifying peer id.
    pub peer_id: [u8; 32],
    /// Pinned Ed25519 public key.
    pub ed: [u8; 32],
    /// Pinned X25519 public key.
    pub dh: [u8; 32],
    /// Digest of the latest bundle, when known.
    pub bundle_digest: Option<[u8; 32]>,
    /// Root of both mailbox chains.
    pub mailbox_root: [u8; 32],
    /// Handshake transcript bound into AEAD.
    pub transcript: Vec<u8>,
    /// Double Ratchet state.
    pub ratchet: RatchetSnapshot,
    /// Out-of-band verification value.
    pub safety_number: [u8; 32],
    /// UNIX seconds when the contact was added.
    pub created_at: u64,
    /// Transcript of the latest accepted handshake (deduplicates retries).
    pub last_handshake: Vec<u8>,
    /// Whether the peer proved possession of its identity key.
    ///
    /// Initiators are verified by the signed bundle. Responders stay
    /// unverified until the first ratchet message decrypts successfully.
    #[serde(default)]
    pub verified: bool,
    /// Epoch whose slot mask is in use.
    pub slot_epoch: u32,
    /// Bitmask of mailbox slots already used in `slot_epoch`.
    pub slot_mask: u32,
}

impl core::fmt::Debug for ContactRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContactRecord")
            .field("peer_id", &hex::encode(self.peer_id))
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl ContactRecord {
    /// Rebuild the pinned public identity.
    pub fn public_identity(&self) -> Result<PublicIdentity> {
        PublicIdentity::from_bytes(&self.ed, &self.dh).map_err(Error::Core)
    }

    /// Verify that the stored `peer_id` still matches the pinned keys.
    pub fn is_consistent(&self) -> bool {
        self.public_identity()
            .map(|identity| identity.peer_id() == self.peer_id)
            .unwrap_or(false)
    }
}

/// Full client state.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientState {
    /// State format version.
    pub version: u32,
    /// Private identity bytes, as produced by [`Identity::to_bytes`].
    pub identity: Vec<u8>,
    /// Private prekeys, as produced by [`PrekeyPair::to_bytes`].
    pub prekeys: Vec<u8>,
    /// Signed prekey bundle published in invites.
    pub bundle: Vec<u8>,
    /// Known relays, in preference order.
    pub relays: Vec<String>,
    /// Conversations.
    pub contacts: Vec<ContactRecord>,
    /// Recently seen message ids (`hex(peer_id) || hex(msg_id)`).
    pub seen: VecDeque<String>,
    /// Outgoing events not yet accepted by any relay.
    #[serde(default)]
    pub outbox: Vec<OutboxRecord>,
    /// Recently received delivery acknowledgements
    /// (`hex(peer_id) || hex(msg_id)`).
    #[serde(default)]
    pub acks: VecDeque<String>,
}

impl core::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientState")
            .field("version", &self.version)
            .field("relays", &self.relays.len())
            .field("contacts", &self.contacts.len())
            .field("seen", &self.seen.len())
            .field("outbox", &self.outbox.len())
            .field("acks", &self.acks.len())
            .finish_non_exhaustive()
    }
}

impl ClientState {
    /// Create a fresh state with a new identity and prekeys.
    pub fn generate(relays: Vec<String>) -> Result<Self> {
        let identity = Identity::generate();
        let (prekeys, bundle) = PrekeyPair::generate(&identity);
        Ok(Self {
            version: STATE_VERSION,
            identity: identity.to_bytes().to_vec(),
            prekeys: prekeys.to_bytes().to_vec(),
            bundle: bundle.to_bytes(),
            relays,
            contacts: Vec::new(),
            seen: VecDeque::new(),
            outbox: Vec::new(),
            acks: VecDeque::new(),
        })
    }

    /// Rebuild the private identity.
    pub fn identity(&self) -> Result<Identity> {
        let bytes: [u8; IDENTITY_LEN] = self
            .identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::State("identity length".into()))?;
        Ok(Identity::from_bytes(&bytes))
    }

    /// Rebuild the private prekeys.
    pub fn prekeys(&self) -> Result<PrekeyPair> {
        let bytes: [u8; PREKEY_PAIR_LEN] = self
            .prekeys
            .as_slice()
            .try_into()
            .map_err(|_| Error::State("prekey length".into()))?;
        Ok(PrekeyPair::from_bytes(&bytes))
    }

    /// Parse and verify the published bundle.
    pub fn bundle(&self) -> Result<PrekeyBundle> {
        let bundle = PrekeyBundle::from_bytes(&self.bundle)?;
        bundle.verify()?;
        Ok(bundle)
    }

    /// Peer id of the local identity.
    pub fn peer_id(&self) -> Result<[u8; 32]> {
        Ok(self.identity()?.peer_id())
    }

    /// Find a contact by peer id.
    pub fn contact(&self, peer_id: &[u8; 32]) -> Option<&ContactRecord> {
        self.contacts
            .iter()
            .find(|contact| &contact.peer_id == peer_id)
    }

    /// Find a contact mutably by peer id.
    pub fn contact_mut(&mut self, peer_id: &[u8; 32]) -> Option<&mut ContactRecord> {
        self.contacts
            .iter_mut()
            .find(|contact| &contact.peer_id == peer_id)
    }

    /// Insert or replace a contact.
    pub fn upsert_contact(&mut self, contact: ContactRecord) {
        match self
            .contacts
            .iter_mut()
            .find(|existing| existing.peer_id == contact.peer_id)
        {
            Some(existing) => *existing = contact,
            None => self.contacts.push(contact),
        }
    }

    /// Whether this message id was already processed.
    pub fn seen(&self, peer_id: &[u8; 32], msg_id: &[u8; 16]) -> bool {
        self.seen.contains(&seen_key(peer_id, msg_id))
    }

    /// Remember a processed message id.
    pub fn mark_seen(&mut self, peer_id: &[u8; 32], msg_id: &[u8; 16]) {
        let key = seen_key(peer_id, msg_id);
        if self.seen.contains(&key) {
            return;
        }
        if self.seen.len() >= SEEN_CAPACITY {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
    }

    /// Queue an outgoing event, replacing an existing record for the same id.
    pub fn enqueue_outbox(&mut self, record: OutboxRecord) {
        if let Some(existing) = self
            .outbox
            .iter_mut()
            .find(|existing| existing.msg_id == record.msg_id && existing.peer_id == record.peer_id)
        {
            *existing = record;
            return;
        }
        if self.outbox.len() >= OUTBOX_CAPACITY {
            self.outbox.remove(0);
        }
        self.outbox.push(record);
    }

    /// Remove one outgoing event after a relay accepted it.
    pub fn remove_outbox(&mut self, peer_id: &[u8; 32], msg_id: &[u8; 16]) -> bool {
        let before = self.outbox.len();
        self.outbox
            .retain(|record| record.peer_id != *peer_id || record.msg_id != *msg_id);
        self.outbox.len() != before
    }

    /// Drop expired outgoing events.
    pub fn prune_outbox(&mut self, now: u64) {
        self.outbox.retain(|record| record.expires_at > now);
    }

    /// Whether the peer confirmed decrypting a message.
    pub fn acked(&self, peer_id: &[u8; 32], msg_id: &[u8; 16]) -> bool {
        self.acks.contains(&seen_key(peer_id, msg_id))
    }

    /// Remember a delivery acknowledgement.
    pub fn mark_acked(&mut self, peer_id: &[u8; 32], msg_id: &[u8; 16]) {
        let key = seen_key(peer_id, msg_id);
        if self.acks.contains(&key) {
            return;
        }
        if self.acks.len() >= ACK_CAPACITY {
            self.acks.pop_front();
        }
        self.acks.push_back(key);
    }

    /// Merge relay URLs, preserving order and dropping duplicates.
    pub fn add_relays<I>(&mut self, relays: I)
    where
        I: IntoIterator<Item = String>,
    {
        for relay in relays {
            if !self.relays.contains(&relay) {
                self.relays.push(relay);
            }
        }
    }

    /// Validate structural invariants after loading from disk.
    pub fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION {
            return Err(Error::State(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.identity.len() != IDENTITY_LEN {
            return Err(Error::State("identity length".into()));
        }
        if self.prekeys.len() != PREKEY_PAIR_LEN {
            return Err(Error::State("prekey length".into()));
        }
        self.bundle()?;
        for contact in &self.contacts {
            if !contact.is_consistent() {
                return Err(Error::State("contact keys do not match peer id".into()));
            }
        }
        Ok(())
    }

    /// Compute the safety number with a contact's identity.
    pub fn safety_number(&self, contact: &ContactRecord) -> Result<[u8; 32]> {
        let me = self.identity()?.public();
        let peer = contact.public_identity()?;
        Ok(safety_number(&me, &peer))
    }
}

/// Build a fresh contact record from a completed handshake.
#[allow(clippy::too_many_arguments)]
pub fn new_contact(
    peer: &PublicIdentity,
    bundle_digest: Option<[u8; 32]>,
    mailbox_root: [u8; 32],
    transcript: Vec<u8>,
    ratchet: RatchetSnapshot,
    safety: [u8; 32],
    created_at: u64,
    verified: bool,
) -> ContactRecord {
    ContactRecord {
        peer_id: peer.peer_id(),
        ed: peer.ed_bytes(),
        dh: peer.dh_bytes(),
        bundle_digest,
        mailbox_root,
        transcript: transcript.clone(),
        ratchet,
        safety_number: safety,
        created_at,
        last_handshake: transcript,
        verified,
        slot_epoch: 0,
        slot_mask: 0,
    }
}

/// Current UNIX time helper for new contacts.
pub fn created_now() -> u64 {
    now_unix()
}

/// A fresh 16-byte message id (re-exported for callers building bodies).
pub fn new_msg_id() -> [u8; 16] {
    random_array::<16>()
}

fn seen_key(peer_id: &[u8; 32], msg_id: &[u8; 16]) -> String {
    let mut key = String::with_capacity(96);
    key.push_str(&hex::encode(peer_id));
    key.push_str(&hex::encode(msg_id));
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_state_validates_and_roundtrips_keys() {
        let state = ClientState::generate(vec!["https://relay.example".into()]).unwrap();
        state.validate().unwrap();

        let identity = state.identity().unwrap();
        assert_eq!(identity.peer_id(), state.peer_id().unwrap());
        let prekeys = state.prekeys().unwrap();
        assert_eq!(
            prekeys.signed_prekey_public(),
            state.bundle().unwrap().signed_prekey
        );
    }

    #[test]
    fn dedup_keys_are_bounded_and_distinct_per_peer() {
        let mut state = ClientState::generate(Vec::new()).unwrap();
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        let msg = [3u8; 16];

        assert!(!state.seen(&peer_a, &msg));
        state.mark_seen(&peer_a, &msg);
        state.mark_seen(&peer_a, &msg);
        assert!(state.seen(&peer_a, &msg));
        assert!(!state.seen(&peer_b, &msg));

        for index in 0..SEEN_CAPACITY {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(index as u64).to_le_bytes());
            state.mark_seen(&peer_a, &id);
        }
        assert!(state.seen.len() <= SEEN_CAPACITY);
        assert!(!state.seen(&peer_a, &msg));
    }

    #[test]
    fn outbox_and_acknowledgements_are_deduplicated() {
        let mut state = ClientState::generate(Vec::new()).unwrap();
        let peer = [1u8; 32];
        let record = OutboxRecord {
            msg_id: [2u8; 16],
            peer_id: peer,
            mailbox: [3u8; 32],
            payload: vec![4, 5, 6],
            created_at: 10,
            expires_at: 20,
            attempts: 0,
            next_attempt_at: 0,
        };

        state.enqueue_outbox(record.clone());
        state.enqueue_outbox(record.clone());
        assert_eq!(state.outbox.len(), 1);

        state.prune_outbox(19);
        assert_eq!(state.outbox.len(), 1);
        state.prune_outbox(21);
        assert!(state.outbox.is_empty());

        state.enqueue_outbox(record.clone());
        assert!(state.remove_outbox(&peer, &record.msg_id));
        assert!(!state.remove_outbox(&peer, &record.msg_id));

        assert!(!state.acked(&peer, &[9u8; 16]));
        state.mark_acked(&peer, &[9u8; 16]);
        state.mark_acked(&peer, &[9u8; 16]);
        assert!(state.acked(&peer, &[9u8; 16]));
        assert_eq!(state.acks.len(), 1);
    }

    #[test]
    fn corrupt_state_is_rejected() {
        let mut state = ClientState::generate(Vec::new()).unwrap();
        state.identity.pop();
        assert!(state.validate().is_err());

        let mut state = ClientState::generate(Vec::new()).unwrap();
        state.version = 99;
        assert!(state.validate().is_err());
    }
}
