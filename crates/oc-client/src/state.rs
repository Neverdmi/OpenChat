//! Serialized client state.
//!
//! This structure is never written to disk in plaintext: [`crate::StateStore`]
//! encrypts it with XChaCha20-Poly1305 before touching the filesystem.

use std::collections::VecDeque;

use oc_core::identity::{Identity, PublicIdentity};
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
/// Maximum number of remembered mailbox replay cursors.
pub const CURSOR_CAPACITY: usize = 8192;
/// Rotate signed prekeys and the PQ prekey every seven days.
pub const PREKEY_ROTATION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Number of retired prekeys kept for late handshakes.
pub const RETIRED_PREKEY_CAPACITY: usize = 2;

/// A prekey that was replaced by rotation but still accepts handshakes.
#[derive(Clone, Serialize, Deserialize)]
pub struct RetiredPrekey {
    /// Private prekeys, as produced by [`PrekeyPair::to_bytes`].
    pub bytes: Vec<u8>,
    /// UNIX seconds when the bundle using this prekey was created.
    pub created_at: u64,
}

impl core::fmt::Debug for RetiredPrekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetiredPrekey")
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Last event timestamp seen on one mailbox.
///
/// The relay only filters by one `since` value, so the client tracks a cursor
/// per mailbox and subscribes from the oldest one. After a restart this avoids
/// replaying the whole store while still covering newly opened mailboxes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CursorRecord {
    /// Mailbox public key.
    pub mailbox: [u8; 32],
    /// Day epoch this mailbox belongs to, `None` for the handshake mailbox.
    #[serde(default)]
    pub epoch: Option<u32>,
    /// Newest event timestamp already observed on this mailbox.
    pub last_created_at: u64,
}

impl CursorRecord {
    /// Timestamp to pass to the relay (`since` is exclusive).
    pub fn resume_since(&self) -> u64 {
        self.last_created_at.saturating_sub(1)
    }
}

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
#[serde(deny_unknown_fields)]
pub struct ClientState {
    /// State format version.
    pub version: u32,
    /// Private identity bytes, as produced by [`Identity::to_bytes`].
    pub identity: Vec<u8>,
    /// Current private prekeys, as produced by [`PrekeyPair::to_bytes`].
    pub prekeys: Vec<u8>,
    /// Retired private prekeys, newest first.
    #[serde(default)]
    pub old_prekeys: Vec<RetiredPrekey>,
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
    /// Per-mailbox replay cursors.
    #[serde(default)]
    pub cursors: Vec<CursorRecord>,
}

impl core::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientState")
            .field("version", &self.version)
            .field("relays", &self.relays.len())
            .field("old_prekeys", &self.old_prekeys.len())
            .field("contacts", &self.contacts.len())
            .field("seen", &self.seen.len())
            .field("outbox", &self.outbox.len())
            .field("acks", &self.acks.len())
            .field("cursors", &self.cursors.len())
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
            old_prekeys: Vec::new(),
            bundle: bundle.to_bytes(),
            relays,
            contacts: Vec::new(),
            seen: VecDeque::new(),
            outbox: Vec::new(),
            acks: VecDeque::new(),
            cursors: Vec::new(),
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

    /// Number of usable prekeys: the current one plus retired ones.
    pub fn prekey_count(&self) -> usize {
        1 + self.old_prekeys.len()
    }

    /// Load a prekey by index (`0` is the current one, the rest are retired).
    pub fn prekey_at(&self, index: usize) -> Result<PrekeyPair> {
        let bytes = if index == 0 {
            self.prekeys.as_slice()
        } else {
            self.old_prekeys
                .get(index - 1)
                .ok_or_else(|| Error::State("prekey index out of range".into()))?
                .bytes
                .as_slice()
        };
        let bytes: [u8; PREKEY_PAIR_LEN] = bytes
            .try_into()
            .map_err(|_| Error::State("prekey length".into()))?;
        Ok(PrekeyPair::from_bytes(&bytes))
    }

    /// UNIX seconds when a prekey's bundle was created.
    pub fn prekey_created_at(&self, index: usize) -> Result<u64> {
        if index == 0 {
            Ok(self.bundle()?.created_at)
        } else {
            self.old_prekeys
                .get(index - 1)
                .map(|prekey| prekey.created_at)
                .ok_or_else(|| Error::State("prekey index out of range".into()))
        }
    }

    /// Whether the current prekey is old enough to rotate.
    pub fn prekeys_due(&self, now: u64) -> Result<bool> {
        Ok(now >= self.bundle()?.created_at.saturating_add(PREKEY_ROTATION_SECONDS))
    }

    /// Rotate the signed/PQ prekeys if they are older than seven days.
    pub fn rotate_prekeys_if_due(&mut self, now: u64) -> Result<bool> {
        if !self.prekeys_due(now)? {
            return Ok(false);
        }
        self.rotate_prekeys()?;
        Ok(true)
    }

    /// Generate fresh prekeys, retiring the current pair.
    ///
    /// Retired pairs keep decrypting handshakes addressed to their old
    /// `SPK` mailbox, so invites shared before rotation still work.
    pub fn rotate_prekeys(&mut self) -> Result<()> {
        let identity = self.identity()?;
        let created_at = self.bundle()?.created_at;
        let (prekeys, bundle) = PrekeyPair::generate(&identity);

        let retired = RetiredPrekey {
            bytes: std::mem::take(&mut self.prekeys),
            created_at,
        };
        self.old_prekeys.insert(0, retired);
        self.old_prekeys.truncate(RETIRED_PREKEY_CAPACITY);
        self.prekeys = prekeys.to_bytes().to_vec();
        self.bundle = bundle.to_bytes();
        Ok(())
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
    ///
    /// Eviction is per-peer (audit M-L4): one flooding peer can only
    /// evict its own oldest entries, never another peer's dedup state.
    pub fn mark_seen(&mut self, peer_id: &[u8; 32], msg_id: &[u8; 16]) {
        let key = seen_key(peer_id, msg_id);
        if self.seen.contains(&key) {
            return;
        }
        if self.seen.len() >= SEEN_CAPACITY {
            // Keys are `hex(peer_id) || hex(msg_id)`; evict the oldest
            // entry of this peer, not the global oldest.
            let peer_hex = hex::encode(peer_id);
            if let Some(index) = self
                .seen
                .iter()
                .position(|entry| entry.starts_with(&peer_hex))
            {
                self.seen.remove(index);
            } else {
                self.seen.pop_front();
            }
        }
        self.seen.push_back(key);
    }

    /// Queue an outgoing event, replacing an existing record for the same id.
    ///
    /// A full outbox is an error, never a silent eviction: the ratchet
    /// has already advanced for queued records, so dropping one would
    /// punch a hole in the message sequence (audit H25).
    pub fn enqueue_outbox(&mut self, record: OutboxRecord) -> Result<()> {
        if let Some(existing) = self
            .outbox
            .iter_mut()
            .find(|existing| existing.msg_id == record.msg_id && existing.peer_id == record.peer_id)
        {
            *existing = record;
            return Ok(());
        }
        if self.outbox.len() >= OUTBOX_CAPACITY {
            return Err(Error::State("outbox is full".into()));
        }
        self.outbox.push(record);
        Ok(())
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

    /// Newest event timestamp already observed on `mailbox`.
    pub fn cursor(&self, mailbox: &[u8; 32]) -> Option<u64> {
        self.cursors
            .iter()
            .find(|cursor| &cursor.mailbox == mailbox)
            .map(CursorRecord::resume_since)
    }

    /// Advance the replay cursor for a mailbox.
    ///
    /// The relay-supplied timestamp is clamped to `now + 300s` skew so
    /// one forged far-future event cannot poison the cursor and
    /// permanently filter out legitimate events (audit H20).
    pub fn advance_cursor(&mut self, mailbox: [u8; 32], epoch: Option<u32>, created_at: u64) {
        let created_at = created_at.min(oc_core::now_unix().saturating_add(300));
        if let Some(cursor) = self
            .cursors
            .iter_mut()
            .find(|cursor| cursor.mailbox == mailbox)
        {
            cursor.last_created_at = cursor.last_created_at.max(created_at);
            if epoch.is_some() {
                cursor.epoch = epoch;
            }
            return;
        }

        if self.cursors.len() >= CURSOR_CAPACITY {
            // Drop the oldest cursor; a replay is safe, losing messages is not.
            if let Some((index, _)) = self
                .cursors
                .iter()
                .enumerate()
                .min_by_key(|(_, cursor)| cursor.last_created_at)
            {
                self.cursors.remove(index);
            }
        }
        self.cursors.push(CursorRecord {
            mailbox,
            epoch,
            last_created_at: created_at,
        });
    }

    /// Forget cursors for epochs older than `min_epoch`.
    pub fn prune_cursors(&mut self, min_epoch: u32) {
        self.cursors.retain(|cursor| match cursor.epoch {
            Some(epoch) => epoch >= min_epoch,
            None => true,
        });
    }

    /// Merge relay URLs, preserving order and dropping duplicates.
    /// Maximum configured relays (hint-flood cap, audit M-L2).
    pub const MAX_RELAYS: usize = 32;

    /// Add relays to the configured list (capped, audit M-L2).
    pub fn add_relays<I>(&mut self, relays: I)
    where
        I: IntoIterator<Item = String>,
    {
        for relay in relays {
            if self.relays.len() >= Self::MAX_RELAYS {
                break;
            }
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
        if self.old_prekeys.len() > RETIRED_PREKEY_CAPACITY {
            return Err(Error::State("too many retired prekeys".into()));
        }
        for prekey in &self.old_prekeys {
            if prekey.bytes.len() != PREKEY_PAIR_LEN {
                return Err(Error::State("retired prekey length".into()));
            }
        }
        self.bundle()?;
        // Size caps (audit M-L9): a corrupted or hostile state must not
        // expand into unbounded in-memory structures.
        if self.contacts.len() > 512 {
            return Err(Error::State("too many contacts".into()));
        }
        if self.outbox.len() > OUTBOX_CAPACITY {
            return Err(Error::State("outbox too large".into()));
        }
        if self.cursors.len() > CURSOR_CAPACITY {
            return Err(Error::State("too many cursors".into()));
        }
        let mut peer_ids = std::collections::HashSet::new();
        for contact in &self.contacts {
            if !contact.is_consistent() {
                return Err(Error::State("contact keys do not match peer id".into()));
            }
            if !peer_ids.insert(contact.peer_id) {
                return Err(Error::State("duplicate contact".into()));
            }
            if contact.slot_mask != 0 && contact.slot_mask.count_ones() > 32 {
                return Err(Error::State("invalid slot mask".into()));
            }
        }
        Ok(())
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

        state.enqueue_outbox(record.clone()).unwrap();
        state.enqueue_outbox(record.clone()).unwrap();
        assert_eq!(state.outbox.len(), 1);

        state.prune_outbox(19);
        assert_eq!(state.outbox.len(), 1);
        state.prune_outbox(21);
        assert!(state.outbox.is_empty());

        state.enqueue_outbox(record.clone()).unwrap();
        assert!(state.remove_outbox(&peer, &record.msg_id));
        assert!(!state.remove_outbox(&peer, &record.msg_id));

        assert!(!state.acked(&peer, &[9u8; 16]));
        state.mark_acked(&peer, &[9u8; 16]);
        state.mark_acked(&peer, &[9u8; 16]);
        assert!(state.acked(&peer, &[9u8; 16]));
        assert_eq!(state.acks.len(), 1);
    }

    #[test]
    fn prekey_rotation_retires_but_keeps_old_keys_usable() {
        let mut state = ClientState::generate(Vec::new()).unwrap();
        let first = state.bundle().unwrap();
        let identity = state.identity().unwrap();

        state.rotate_prekeys().unwrap();
        let second = state.bundle().unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_eq!(state.prekey_count(), 2);
        assert_eq!(
            state.prekey_at(0).unwrap().signed_prekey_public(),
            second.signed_prekey
        );
        assert_eq!(
            state.prekey_at(1).unwrap().signed_prekey_public(),
            first.signed_prekey
        );

        // A handshake addressed to the retired prekey still agrees.
        let alice = Identity::generate();
        let (initiation, alice_key) = oc_core::x3dh::initiate(&alice, &first).unwrap();
        let bob_key =
            oc_core::x3dh::respond(&identity, &state.prekey_at(1).unwrap(), &initiation).unwrap();
        assert_eq!(alice_key, bob_key);

        for _ in 0..4 {
            state.rotate_prekeys().unwrap();
        }
        assert_eq!(state.old_prekeys.len(), RETIRED_PREKEY_CAPACITY);
        state.validate().unwrap();
    }

    #[test]
    fn cursor_resume_is_exclusive_and_old_epochs_are_pruned() {
        let mut state = ClientState::generate(Vec::new()).unwrap();
        let mailbox = [4u8; 32];

        assert_eq!(state.cursor(&mailbox), None);
        state.advance_cursor(mailbox, Some(10), 100);
        assert_eq!(state.cursor(&mailbox), Some(99));

        // A later event moves the cursor forward, never backwards.
        state.advance_cursor(mailbox, Some(10), 500);
        state.advance_cursor(mailbox, Some(10), 400);
        assert_eq!(state.cursor(&mailbox), Some(499));

        let next_epoch = [5u8; 32];
        let handshake = [6u8; 32];
        state.advance_cursor(next_epoch, Some(11), 700);
        state.advance_cursor(handshake, None, 800);
        state.prune_cursors(10);
        assert!(state.cursor(&next_epoch).is_some());
        assert!(state.cursor(&handshake).is_some());

        state.prune_cursors(12);
        assert!(state.cursor(&next_epoch).is_none());
        assert!(state.cursor(&handshake).is_some());
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
