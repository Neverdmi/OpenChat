//! High-level client: invites, handshakes, text messages and receiving.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use oc_core::identity::{PublicIdentity, safety_number};
use oc_core::mailbox::{self, MailboxChain, SLOTS_PER_EPOCH};
use oc_core::ratchet::Ratchet;
use oc_core::seal;
use oc_core::x3dh::{self, Initiation, PrekeyPair};
use oc_core::{frame, now_unix, random_array};
use oc_transport::RelayPool;
use oc_wire::RelayEvent;

use crate::invite::Invite;
use crate::message::{Envelope, TextBody};
use crate::state::{ClientState, ContactRecord, created_now, new_contact};
use crate::store::StateStore;
use crate::{Error, Result};

/// Default number of relays to publish to.
pub const DEFAULT_FANOUT: usize = 3;
/// Lifetime of a queued message on relays.
pub const MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Lifetime of a queued handshake on relays.
pub const HANDSHAKE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Summary returned after adding a contact.
#[derive(Clone, Debug)]
pub struct ContactSummary {
    /// Peer id of the new contact.
    pub peer_id: [u8; 32],
    /// Safety number for out-of-band verification.
    pub safety_number: [u8; 32],
    /// Number of relays that accepted the handshake.
    pub delivered: usize,
}

/// Result of sending one text message.
#[derive(Clone, Debug)]
pub struct SentMessage {
    /// Random message id.
    pub msg_id: [u8; 16],
    /// Number of relays that accepted the event.
    pub delivered: usize,
}

/// A decrypted incoming message.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// Sender peer id.
    pub peer_id: [u8; 32],
    /// Random message id.
    pub msg_id: [u8; 16],
    /// Sender wall-clock time in milliseconds.
    pub timestamp_ms: u64,
    /// UTF-8 text.
    pub text: String,
}

#[derive(Clone)]
enum MailboxRef {
    Handshake { secret: [u8; 32] },
    Inbox { peer_id: [u8; 32], secret: [u8; 32] },
}

type SubscriptionMap = HashMap<[u8; 32], MailboxRef>;

enum Processed {
    Ignored,
    Message(ReceivedMessage),
    ContactAdded,
}

/// OpenChat client: encrypted state plus protocol operations.
pub struct Client {
    state: ClientState,
    store: StateStore,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("peer_id", &self.peer_id().map(hex::encode))
            .field("contacts", &self.state.contacts.len())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Create a new identity and persist it.
    pub fn create(store: StateStore, relays: Vec<String>) -> Result<Self> {
        let state = ClientState::generate(relays)?;
        store.save(&state)?;
        Ok(Self { state, store })
    }

    /// Open and validate existing state.
    pub fn open(store: StateStore) -> Result<Self> {
        let state = store.load()?;
        Ok(Self { state, store })
    }

    /// Local peer id.
    pub fn peer_id(&self) -> Result<[u8; 32]> {
        self.state.peer_id()
    }

    /// Local public identity.
    pub fn public_identity(&self) -> Result<PublicIdentity> {
        Ok(self.state.identity()?.public())
    }

    /// Known relays.
    pub fn relays(&self) -> &[String] {
        &self.state.relays
    }

    /// Known contacts.
    pub fn contacts(&self) -> &[ContactRecord] {
        &self.state.contacts
    }

    /// Find a contact by peer id.
    pub fn contact(&self, peer_id: &[u8; 32]) -> Option<&ContactRecord> {
        self.state.contact(peer_id)
    }

    /// Build the invite link for this identity.
    pub fn invite(&self) -> Result<String> {
        let invite = Invite::new(self.state.bundle()?, self.state.relays.clone())?;
        Ok(invite.encode())
    }

    /// Persist current state.
    pub fn save(&self) -> Result<()> {
        self.store.save(&self.state)
    }

    /// Add relay hints and persist.
    pub fn add_relays(&mut self, relays: Vec<String>) -> Result<()> {
        self.state.add_relays(relays);
        self.save()
    }

    /// Add a contact from an invite and publish the X3DH initiation.
    pub async fn add_invite(
        &mut self,
        invite_text: &str,
        pool: &RelayPool,
        fanout: usize,
    ) -> Result<ContactSummary> {
        let invite = Invite::decode(invite_text)?;
        let me = self.state.identity()?;
        let my_public = me.public();

        // TOFU: pin the long-term identity, never silently replace a
        // confirmed contact. An unverified record may be replaced because the
        // previous handshake was never proved by a ratchet message.
        if let Some(existing) = self.state.contact(&invite.peer_id) {
            let keys_changed = existing.ed != invite.bundle.identity.ed_bytes()
                || existing.dh != invite.bundle.identity.dh_bytes();
            if keys_changed && existing.verified {
                return Err(Error::Tofu);
            }
        }

        let (initiation, session_key) = x3dh::initiate(&me, &invite.bundle)?;
        let transcript = x3dh::transcript(&initiation, &invite.bundle.identity);
        let ratchet = Ratchet::new_initiator(
            &session_key,
            &invite.bundle.signed_prekey,
            transcript.clone(),
        );
        let mailbox_root = x3dh::mailbox_root(&session_key);
        let safety = safety_number(&my_public, &invite.bundle.identity);

        let existing_created_at = self
            .state
            .contact(&invite.peer_id)
            .map(|contact| contact.created_at)
            .unwrap_or_else(created_now);

        let contact = new_contact(
            &invite.bundle.identity,
            Some(invite.bundle.digest()),
            mailbox_root,
            transcript,
            ratchet.snapshot(),
            safety,
            existing_created_at,
            true,
        );

        // Handshake goes to the responder's signed prekey, which doubles as
        // a one-time-friendly ECIES mailbox before any session exists.
        let padded = frame::pad(&initiation.to_bytes())?;
        let inner = Envelope::handshake(padded).encode();
        let sealed = seal::seal(&invite.bundle.signed_prekey, &inner)?;
        let event = RelayEvent::new(invite.bundle.signed_prekey, sealed, HANDSHAKE_TTL_SECONDS);
        let delivered = pool.publish(&event, fanout.max(1)).await?;

        self.state.upsert_contact(contact);
        self.state.add_relays(invite.relays);
        self.save()?;

        Ok(ContactSummary {
            peer_id: invite.peer_id,
            safety_number: safety,
            delivered,
        })
    }

    /// Encrypt and publish one text message.
    pub async fn send_text(
        &mut self,
        peer_id: &[u8; 32],
        text: &str,
        pool: &RelayPool,
        fanout: usize,
    ) -> Result<SentMessage> {
        let my_peer_id = self.state.peer_id()?;
        let contact = self.state.contact(peer_id).ok_or(Error::UnknownContact)?;

        let body = TextBody::new(text)?;
        let padded = frame::pad(&body.encode()?)?;

        let mut ratchet = Ratchet::from_snapshot(contact.ratchet.clone())?;
        let (header, ciphertext) = match ratchet.encrypt(&padded) {
            Ok(result) => result,
            Err(oc_core::Error::RatchetState) => return Err(Error::SessionNotReady),
            Err(error) => return Err(Error::Core(error)),
        };

        let inner = Envelope::text(header, ciphertext).encode();
        let epoch = mailbox::epoch_of(now_unix());
        let (mailbox_root, peer) = (contact.mailbox_root, contact.peer_id);
        let slot = {
            let contact = self
                .state
                .contact_mut(peer_id)
                .ok_or(Error::UnknownContact)?;
            pick_slot(contact, epoch)
        };

        // Peer's inbox: owner = peer, sender = self.
        let chain = MailboxChain::derive(&mailbox_root, &peer, &my_peer_id);
        let mailbox_pk = chain.slot_public(epoch, slot);
        let sealed = seal::seal(&mailbox_pk, &inner)?;

        let event = RelayEvent::new(mailbox_pk, sealed, MESSAGE_TTL_SECONDS);
        let delivered = pool.publish(&event, fanout.max(1)).await?;

        let contact = self
            .state
            .contact_mut(peer_id)
            .ok_or(Error::UnknownContact)?;
        contact.ratchet = ratchet.snapshot();
        self.state.mark_seen(peer_id, &body.msg_id);
        self.save()?;

        Ok(SentMessage {
            msg_id: body.msg_id,
            delivered,
        })
    }

    /// Receive and decrypt available events, returning after `idle` with no
    /// new events.
    pub async fn listen_once(
        &mut self,
        pool: &RelayPool,
        idle: Duration,
        since: u64,
    ) -> Result<Vec<ReceivedMessage>> {
        let mut received = Vec::new();

        loop {
            let (mailboxes, map) = self.subscriptions()?;
            if mailboxes.is_empty() {
                return Ok(received);
            }

            let mut stream = pool.subscribe_all_many(&mailboxes, since).await?;
            let mut restart = false;

            loop {
                match tokio::time::timeout(idle, stream.next()).await {
                    Err(_) => break,
                    Ok(None) => break,
                    Ok(Some(Err(error))) => return Err(error.into()),
                    Ok(Some(Ok(event))) => match self.process_event(&map, &event)? {
                        Processed::Ignored => {}
                        Processed::Message(message) => received.push(message),
                        Processed::ContactAdded => {
                            // New contact means new inbox mailboxes: rebuild
                            // the subscription and replay from the relay.
                            restart = true;
                            break;
                        }
                    },
                }
            }

            if !restart {
                break;
            }
        }

        Ok(received)
    }

    fn subscriptions(&self) -> Result<(Vec<[u8; 32]>, SubscriptionMap)> {
        let me = self.state.peer_id()?;
        let prekeys = self.state.prekeys()?;
        let mut map = HashMap::new();

        let handshake = prekeys.signed_prekey_public();
        map.insert(
            handshake,
            MailboxRef::Handshake {
                secret: prekeys.signed_prekey.to_bytes(),
            },
        );

        let epoch = mailbox::epoch_of(now_unix());
        for contact in &self.state.contacts {
            // Our inbox: owner = self, peer = contact.
            let chain = MailboxChain::derive(&contact.mailbox_root, &me, &contact.peer_id);
            for current in [epoch, epoch.wrapping_add(1)] {
                for index in 0..SLOTS_PER_EPOCH {
                    let public = chain.slot_public(current, index);
                    map.insert(
                        public,
                        MailboxRef::Inbox {
                            peer_id: contact.peer_id,
                            secret: chain.slot_secret(current, index),
                        },
                    );
                }
            }
        }

        let mailboxes = map.keys().copied().collect();
        Ok((mailboxes, map))
    }

    fn process_event(
        &mut self,
        map: &HashMap<[u8; 32], MailboxRef>,
        event: &RelayEvent,
    ) -> Result<Processed> {
        match map.get(&event.mailbox).cloned() {
            Some(MailboxRef::Handshake { secret }) => {
                self.process_handshake(&secret, &event.payload)
            }
            Some(MailboxRef::Inbox { peer_id, secret }) => {
                self.process_text(&peer_id, &secret, &event.payload)
            }
            None => Ok(Processed::Ignored),
        }
    }

    fn process_handshake(&mut self, secret: &[u8; 32], payload: &[u8]) -> Result<Processed> {
        let plaintext = match seal::open(secret, payload) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(Processed::Ignored),
        };
        let padded = match Envelope::decode(&plaintext) {
            Ok(Envelope::Handshake(padded)) => padded,
            _ => return Ok(Processed::Ignored),
        };
        let initiation_bytes = match frame::unpad(&padded) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(Processed::Ignored),
        };
        let initiation = match Initiation::from_bytes(initiation_bytes) {
            Ok(initiation) => initiation,
            Err(_) => return Ok(Processed::Ignored),
        };

        let me = self.state.identity()?;
        let my_public = me.public();
        let peer_id = initiation.initiator.peer_id();

        // TOFU: a confirmed contact may not change long-term keys. An
        // unverified record produced by an earlier handshake may be replaced
        // until a ratchet message proves possession of the identity key.
        if let Some(existing) = self.state.contact(&peer_id) {
            let keys_changed = existing.ed != initiation.initiator.ed_bytes()
                || existing.dh != initiation.initiator.dh_bytes();
            if keys_changed && existing.verified {
                return Err(Error::Tofu);
            }
        }

        let prekeys = self.state.prekeys()?;
        let session_key = match x3dh::respond(&me, &prekeys, &initiation) {
            Ok(session_key) => session_key,
            Err(_) => return Ok(Processed::Ignored),
        };
        let transcript = x3dh::transcript(&initiation, &my_public);

        if let Some(existing) = self.state.contact(&peer_id) {
            if existing.last_handshake == transcript {
                return Ok(Processed::Ignored);
            }
        }

        let PrekeyPair { signed_prekey, .. } = prekeys;
        let ratchet = Ratchet::new_responder(&session_key, signed_prekey, transcript.clone());
        let mailbox_root = x3dh::mailbox_root(&session_key);
        let safety = safety_number(&my_public, &initiation.initiator);

        let existing = self.state.contact(&peer_id);
        let bundle_digest = existing.and_then(|contact| contact.bundle_digest);
        let created_at = existing
            .map(|contact| contact.created_at)
            .unwrap_or_else(created_now);

        let contact = new_contact(
            &initiation.initiator,
            bundle_digest,
            mailbox_root,
            transcript,
            ratchet.snapshot(),
            safety,
            created_at,
            false,
        );
        self.state.upsert_contact(contact);
        self.save()?;
        Ok(Processed::ContactAdded)
    }

    fn process_text(
        &mut self,
        peer_id: &[u8; 32],
        secret: &[u8; 32],
        payload: &[u8],
    ) -> Result<Processed> {
        let plaintext = match seal::open(secret, payload) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(Processed::Ignored),
        };
        let (header, ciphertext) = match Envelope::decode(&plaintext) {
            Ok(Envelope::Text { header, ciphertext }) => (header, ciphertext),
            _ => return Ok(Processed::Ignored),
        };

        let contact = self.state.contact(peer_id).ok_or(Error::UnknownContact)?;
        let mut ratchet = Ratchet::from_snapshot(contact.ratchet.clone())?;
        let padded = match ratchet.decrypt(&header, &ciphertext) {
            Ok(padded) => padded,
            Err(_) => return Ok(Processed::Ignored),
        };
        let body_bytes = match frame::unpad(&padded) {
            Ok(body) => body,
            Err(_) => return Ok(Processed::Ignored),
        };
        let body = match TextBody::decode(body_bytes) {
            Ok(body) => body,
            Err(_) => return Ok(Processed::Ignored),
        };

        // A successful ratchet decrypt proves the peer holds the private
        // identity key behind the pinned public keys.
        let already_seen = self.state.seen(peer_id, &body.msg_id);
        let contact = self
            .state
            .contact_mut(peer_id)
            .ok_or(Error::UnknownContact)?;
        let was_unverified = !contact.verified;
        contact.verified = true;

        if already_seen {
            if was_unverified {
                self.save()?;
            }
            return Ok(Processed::Ignored);
        }

        contact.ratchet = ratchet.snapshot();
        self.state.mark_seen(peer_id, &body.msg_id);
        self.save()?;

        Ok(Processed::Message(ReceivedMessage {
            peer_id: *peer_id,
            msg_id: body.msg_id,
            timestamp_ms: body.timestamp_ms,
            text: body.text,
        }))
    }
}

/// Pick an unused mailbox slot for `epoch`, resetting the mask when exhausted.
fn pick_slot(contact: &mut ContactRecord, epoch: u32) -> u32 {
    if contact.slot_epoch != epoch {
        contact.slot_epoch = epoch;
        contact.slot_mask = 0;
    }

    let mut available = !contact.slot_mask;
    if available == 0 {
        contact.slot_mask = 0;
        available = u32::MAX;
    }

    let start = u32::from_le_bytes(random_array::<4>()) % SLOTS_PER_EPOCH;
    let mut slot = start;
    for _ in 0..SLOTS_PER_EPOCH {
        let bit = 1u32 << slot;
        if available & bit != 0 {
            contact.slot_mask |= bit;
            return slot;
        }
        slot = (slot + 1) % SLOTS_PER_EPOCH;
    }
    // All 32 bits were available above, so this is unreachable.
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ContactRecord;
    use oc_core::ratchet::RatchetSnapshot;

    fn empty_contact() -> ContactRecord {
        ContactRecord {
            peer_id: [1u8; 32],
            ed: [2u8; 32],
            dh: [3u8; 32],
            bundle_digest: None,
            mailbox_root: [4u8; 32],
            transcript: Vec::new(),
            ratchet: RatchetSnapshot {
                root_key: [0u8; 32],
                self_dh: [5u8; 32],
                self_dh_public: [6u8; 32],
                remote_dh: None,
                send_chain: None,
                recv_chain: None,
                send_count: 0,
                prev_send_count: 0,
                recv_count: 0,
                skipped: Vec::new(),
                transcript: Vec::new(),
                max_skip: oc_core::ratchet::MAX_SKIP,
            },
            safety_number: [0u8; 32],
            created_at: 0,
            last_handshake: Vec::new(),
            verified: false,
            slot_epoch: 0,
            slot_mask: 0,
        }
    }

    #[test]
    fn slots_rotate_within_epoch_and_reset_on_the_next() {
        let mut contact = empty_contact();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..SLOTS_PER_EPOCH {
            let slot = pick_slot(&mut contact, 10);
            assert!(slot < SLOTS_PER_EPOCH);
            assert!(seen.insert(slot));
        }
        assert_eq!(contact.slot_mask, u32::MAX);

        // Exhausted mask resets and is reusable.
        let slot = pick_slot(&mut contact, 10);
        assert!(slot < SLOTS_PER_EPOCH);
        assert_eq!(contact.slot_mask.count_ones(), 1);

        let slot = pick_slot(&mut contact, 11);
        assert!(slot < SLOTS_PER_EPOCH);
        assert_eq!(contact.slot_epoch, 11);
        assert_eq!(contact.slot_mask.count_ones(), 1);
    }
}
