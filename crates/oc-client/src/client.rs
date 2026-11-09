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
use crate::message::{AckBody, Body, Envelope, TextBody};
use crate::state::{ClientState, ContactRecord, OutboxRecord, created_now, new_contact};
use crate::store::StateStore;
use crate::webrtc::{Signaling, WebRtcSession};
use crate::{Error, Result};

/// Default number of relays to publish to.
pub const DEFAULT_FANOUT: usize = 3;
/// Lifetime of a queued message on relays.
pub const MESSAGE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Lifetime of a queued handshake on relays.
pub const HANDSHAKE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// First retry delay for a queued event.
pub const OUTBOX_BASE_DELAY_SECONDS: u64 = 5;
/// Upper bound for the exponential retry delay.
pub const OUTBOX_MAX_DELAY_SECONDS: u64 = 300;

/// Summary returned after adding a contact.
#[derive(Clone, Debug)]
pub struct ContactSummary {
    /// Peer id of the new contact.
    pub peer_id: [u8; 32],
    /// Safety number for out-of-band verification.
    pub safety_number: [u8; 32],
    /// Number of relays that accepted the handshake.
    pub delivered: usize,
    /// Whether the handshake is still waiting in the outbox.
    pub queued: bool,
}

/// Result of sending one text message.
#[derive(Clone, Debug)]
pub struct SentMessage {
    /// Random message id.
    pub msg_id: [u8; 16],
    /// Number of relays that accepted the event.
    pub delivered: usize,
    /// Whether the message is still waiting in the outbox.
    pub queued: bool,
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

/// A delivery acknowledgement from a peer.
#[derive(Clone, Debug)]
pub struct ReceivedAck {
    /// Peer that confirmed decryption.
    pub peer_id: [u8; 32],
    /// Message id that was decrypted.
    pub acked_msg_id: [u8; 16],
}

/// Everything that happened during one receive pass.
#[derive(Clone, Debug, Default)]
pub struct ListenOutcome {
    /// Decrypted text messages, in arrival order.
    pub messages: Vec<ReceivedMessage>,
    /// Delivery acknowledgements.
    pub acks: Vec<ReceivedAck>,
    /// Contacts learned from successful handshakes.
    pub added_contacts: Vec<[u8; 32]>,
}

#[derive(Clone)]
enum MailboxRef {
    Handshake {
        prekey: usize,
        created_at: u64,
        secret: [u8; 32],
    },
    Inbox {
        peer_id: [u8; 32],
        epoch: u32,
        secret: [u8; 32],
    },
    Signaling {
        peer_id: [u8; 32],
        secret: [u8; 32],
    },
}

type SubscriptionMap = HashMap<[u8; 32], MailboxRef>;

enum Processed {
    Ignored,
    Message(ReceivedMessage),
    Ack(ReceivedAck),
    ContactAdded([u8; 32]),
}

/// How often the signed bundle is re-published to the bundle mailbox,
/// in seconds. Live-only carriers (MQTT) keep nothing, so the bundle
/// must be refreshed while the owner is online.
const BUNDLE_PUBLISH_INTERVAL: u64 = 300;
/// How long to wait for a bundle when following a short invite.
const BUNDLE_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// OpenChat client: encrypted state plus protocol operations.
pub struct Client {
    state: ClientState,
    store: StateStore,
    /// Last bundle publish (UNIX seconds, session-only throttle).
    last_bundle_publish: u64,
    /// Whether WebRTC direct delivery is attempted (opt-in).
    webrtc_enabled: bool,
    /// Live WebRTC sessions by peer id (session-only, never persisted).
    webrtc_sessions: HashMap<[u8; 32], WebRtcSession>,
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
        Ok(Self {
            state,
            store,
            last_bundle_publish: 0,
            webrtc_enabled: false,
            webrtc_sessions: HashMap::new(),
        })
    }

    /// Open and validate existing state, rotating prekeys when due.
    pub fn open(store: StateStore) -> Result<Self> {
        let mut state = store.load()?;
        if state.rotate_prekeys_if_due(now_unix())? {
            store.save(&state)?;
        }
        Ok(Self {
            state,
            store,
            last_bundle_publish: 0,
            webrtc_enabled: false,
            webrtc_sessions: HashMap::new(),
        })
    }

    /// Enable or disable WebRTC direct delivery (opt-in).
    pub fn set_webrtc(&mut self, enabled: bool) {
        self.webrtc_enabled = enabled;
        if !enabled {
            self.webrtc_sessions.clear();
        }
    }

    /// Whether WebRTC direct delivery is attempted.
    pub fn is_webrtc(&self) -> bool {
        self.webrtc_enabled
    }

    /// Whether a WebRTC data channel to the peer is currently open.
    pub async fn webrtc_session_open(&self, peer_id: &[u8; 32]) -> bool {
        match self.webrtc_sessions.get(peer_id) {
            Some(session) => session.is_open().await,
            None => false,
        }
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
    ///
    /// Short form: peer id only (~70 characters). Built-in default
    /// relays are not embedded as hints either — every client already
    /// has them. The invitee fetches the signed bundle from this
    /// client's bundle mailbox (SPEC §4.2).
    pub fn invite(&self) -> Result<String> {
        let peer_id = self.state.peer_id()?;
        let invite = Invite::short(peer_id, invite_hints(&self.state.relays))?;
        Ok(invite.encode())
    }

    /// Build a full invite with the bundle embedded.
    ///
    /// Works without a bundle fetch (the invitee need not wait for the
    /// owner to be online), at the cost of a much longer link. Prefer
    /// the short [`Client::invite`] unless offline exchange matters.
    pub fn invite_full(&self) -> Result<String> {
        let invite = Invite::new(self.state.bundle()?, invite_hints(&self.state.relays))?;
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

    /// Generate fresh prekeys now, keeping recent ones for late handshakes.
    pub fn rotate_prekeys(&mut self) -> Result<()> {
        self.state.rotate_prekeys()?;
        self.save()
    }

    /// Number of prekeys that still accept handshakes (current + retired).
    pub fn prekey_count(&self) -> usize {
        self.state.prekey_count()
    }

    /// Add a contact from an invite and publish the X3DH initiation.
    pub async fn add_invite(
        &mut self,
        invite_text: &str,
        pool: &RelayPool,
        fanout: usize,
    ) -> Result<ContactSummary> {
        let invite = Invite::decode(invite_text)?;
        let bundle = match invite.bundle.clone() {
            Some(bundle) => bundle,
            None => fetch_bundle(pool, &invite.peer_id).await?,
        };
        let me = self.state.identity()?;
        let my_public = me.public();

        // TOFU: pin the long-term identity, never silently replace a
        // confirmed contact. An unverified record may be replaced because the
        // previous handshake was never proved by a ratchet message.
        if let Some(existing) = self.state.contact(&invite.peer_id) {
            let keys_changed = existing.ed != bundle.identity.ed_bytes()
                || existing.dh != bundle.identity.dh_bytes();
            if keys_changed && existing.verified {
                return Err(Error::Tofu);
            }
        }

        let (initiation, session_key) = x3dh::initiate(&me, &bundle)?;
        let transcript = x3dh::transcript(&initiation, &bundle.identity);
        let ratchet = Ratchet::new_initiator(
            &session_key,
            &bundle.signed_prekey,
            transcript.clone(),
        );
        let mailbox_root = x3dh::mailbox_root(&session_key);
        let safety = safety_number(&my_public, &bundle.identity);

        let existing_created_at = self
            .state
            .contact(&invite.peer_id)
            .map(|contact| contact.created_at)
            .unwrap_or_else(created_now);

        let contact = new_contact(
            &bundle.identity,
            Some(bundle.digest()),
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
        let sealed = seal::seal(&bundle.signed_prekey, &inner)?;
        let now = now_unix();
        let record = OutboxRecord {
            msg_id: random_array::<16>(),
            peer_id: invite.peer_id,
            mailbox: bundle.signed_prekey,
            payload: sealed,
            created_at: now,
            expires_at: now.saturating_add(HANDSHAKE_TTL_SECONDS),
            attempts: 0,
            next_attempt_at: 0,
        };

        self.state.upsert_contact(contact);
        self.state.add_relays(invite.relays);
        self.state.enqueue_outbox(record.clone());
        self.save()?;
        let delivered = self.try_deliver(&record, pool, fanout).await;
        self.save()?;

        Ok(ContactSummary {
            peer_id: invite.peer_id,
            safety_number: safety,
            delivered,
            queued: delivered == 0,
        })
    }

    /// Encrypt and publish one text message.
    ///
    /// The ciphertext is written to the outbox before the first publish
    /// attempt, so a relay outage never loses a message that already advanced
    /// the ratchet. If every relay is unreachable the message stays queued and
    /// `queued` is set.
    pub async fn send_text(
        &mut self,
        peer_id: &[u8; 32],
        text: &str,
        pool: &RelayPool,
        fanout: usize,
    ) -> Result<SentMessage> {
        let body = TextBody::new(text)?;
        let msg_id = body.msg_id;
        let record = self.seal_body(peer_id, &Body::Text(body), MESSAGE_TTL_SECONDS)?;

        self.state.enqueue_outbox(record.clone());
        self.save()?;

        // WebRTC direct delivery first (opt-in): if the peer's data
        // channel is open, the sealed payload goes P2P and never
        // touches a relay. Otherwise fall back to the relay pool.
        if self.webrtc_enabled && self.webrtc_send(peer_id, &record, pool).await {
            self.state.remove_outbox(&record.peer_id, &record.msg_id);
            self.save()?;
            return Ok(SentMessage {
                msg_id,
                delivered: 1,
                queued: false,
            });
        }

        let delivered = self.try_deliver(&record, pool, fanout).await;
        self.save()?;

        Ok(SentMessage {
            msg_id,
            delivered,
            queued: delivered == 0,
        })
    }

    /// Try to deliver one queued record over the peer's WebRTC data
    /// channel, starting a session (offer) when necessary.
    /// Returns true when the payload was handed to the channel.
    async fn webrtc_send(&mut self, peer_id: &[u8; 32], record: &OutboxRecord, pool: &RelayPool) -> bool {
        if !self.webrtc_sessions.contains_key(peer_id) {
            let own = match self.state.peer_id() {
                Ok(own) => own,
                Err(_) => return false,
            };
            match WebRtcSession::new(true, own).await {
                Ok(session) => {
                    self.webrtc_sessions.insert(*peer_id, session);
                }
                Err(_) => return false,
            }
        }
        // (Re-)offer while no remote description has arrived yet, and
        // collect gathered ICE candidates. Signaling is published after
        // the session borrow ends.
        let mut to_publish: Vec<Signaling> = Vec::new();
        let open = {
            let Some(session) = self.webrtc_sessions.get_mut(peer_id) else {
                return false;
            };
            let now = now_unix();
            if session.needs_offer(now) {
                match session.offer().await {
                    Ok(offer) => to_publish.push(offer),
                    Err(_) => return false,
                }
            }
            to_publish.extend(session.take_outbound());
            session.is_open().await
        };
        for signaling in to_publish {
            self.publish_signaling(pool, peer_id, &signaling).await;
        }
        if !open {
            return false;
        }
        let event = RelayEvent {
            mailbox: record.mailbox,
            created_at: record.created_at,
            expires_at: record.expires_at,
            payload: record.payload.clone(),
        };
        let bytes = match serde_json::to_vec(&event) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        match self.webrtc_sessions.get(peer_id) {
            Some(session) => session.send(bytes).await.is_ok(),
            None => false,
        }
    }

    /// Publish one signaling message to the peer's signaling mailbox.
    async fn publish_signaling(&self, pool: &RelayPool, peer_id: &[u8; 32], signaling: &Signaling) {
        let mailbox = mailbox::signaling_mailbox_public(peer_id);
        let plaintext = match serde_json::to_vec(signaling) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let payload = match seal::seal(&mailbox, &plaintext) {
            Ok(payload) => payload,
            Err(_) => return,
        };
        let now = now_unix();
        let event = RelayEvent {
            mailbox,
            created_at: now,
            expires_at: now.saturating_add(MESSAGE_TTL_SECONDS),
            payload,
        };
        let _ = pool.publish(&event, DEFAULT_FANOUT).await;
    }

    /// Outgoing events still waiting for a relay.
    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.state.outbox
    }

    /// Whether the peer confirmed decrypting a message.
    pub fn is_acked(&self, peer_id: &[u8; 32], msg_id: &[u8; 16]) -> bool {
        self.state.acked(peer_id, msg_id)
    }

    /// Retry every queued event now, ignoring backoff timers.
    pub async fn flush_outbox(&mut self, pool: &RelayPool, fanout: usize) -> Result<usize> {
        self.flush_outbox_inner(pool, fanout, false).await
    }

    /// Retry queued events whose backoff timer has elapsed.
    pub async fn flush_due_outbox(&mut self, pool: &RelayPool, fanout: usize) -> Result<usize> {
        self.flush_outbox_inner(pool, fanout, true).await
    }

    async fn flush_outbox_inner(
        &mut self,
        pool: &RelayPool,
        fanout: usize,
        only_due: bool,
    ) -> Result<usize> {
        let now = now_unix();
        self.state.prune_outbox(now);

        let due: Vec<OutboxRecord> = self
            .state
            .outbox
            .iter()
            .filter(|record| !only_due || record.next_attempt_at <= now)
            .cloned()
            .collect();

        let mut delivered = 0usize;
        for record in due {
            if self.try_deliver(&record, pool, fanout).await > 0 {
                delivered += 1;
                continue;
            }
            if let Some(entry) = self
                .state
                .outbox
                .iter_mut()
                .find(|entry| entry.msg_id == record.msg_id && entry.peer_id == record.peer_id)
            {
                entry.attempts = entry.attempts.saturating_add(1);
                let shift = entry.attempts.min(6);
                let delay = OUTBOX_BASE_DELAY_SECONDS
                    .saturating_mul(1u64 << shift)
                    .min(OUTBOX_MAX_DELAY_SECONDS);
                entry.next_attempt_at = now.saturating_add(delay);
            }
        }

        self.save()?;
        Ok(delivered)
    }

    /// Seal one application body into the peer's inbox and update the ratchet.
    fn seal_body(&mut self, peer_id: &[u8; 32], body: &Body, ttl: u64) -> Result<OutboxRecord> {
        let my_peer_id = self.state.peer_id()?;
        let contact = self.state.contact(peer_id).ok_or(Error::UnknownContact)?;

        let padded = frame::pad(&body.encode()?)?;
        let mut ratchet = Ratchet::from_snapshot(contact.ratchet.clone())?;
        let (header, ciphertext) = match ratchet.encrypt(&padded) {
            Ok(result) => result,
            Err(oc_core::Error::RatchetState) => return Err(Error::SessionNotReady),
            Err(error) => return Err(Error::Core(error)),
        };
        let inner = Envelope::text(header, ciphertext).encode();

        let epoch = mailbox::epoch_of(now_unix());
        let mailbox_root = contact.mailbox_root;
        let slot = {
            let contact = self
                .state
                .contact_mut(peer_id)
                .ok_or(Error::UnknownContact)?;
            pick_slot(contact, epoch)
        };

        // Peer's inbox: owner = peer, sender = self.
        let chain = MailboxChain::derive(&mailbox_root, peer_id, &my_peer_id);
        let mailbox = chain.slot_public(epoch, slot);
        let payload = seal::seal(&mailbox, &inner)?;

        let msg_id = body.msg_id();
        let contact = self
            .state
            .contact_mut(peer_id)
            .ok_or(Error::UnknownContact)?;
        contact.ratchet = ratchet.snapshot();
        self.state.mark_seen(peer_id, &msg_id);

        let now = now_unix();
        Ok(OutboxRecord {
            msg_id,
            peer_id: *peer_id,
            mailbox,
            payload,
            created_at: now,
            expires_at: now.saturating_add(ttl),
            attempts: 0,
            next_attempt_at: 0,
        })
    }

    /// Publish one queued record and remove it on success.
    async fn try_deliver(
        &mut self,
        record: &OutboxRecord,
        pool: &RelayPool,
        fanout: usize,
    ) -> usize {
        let event = RelayEvent {
            mailbox: record.mailbox,
            created_at: record.created_at,
            expires_at: record.expires_at,
            payload: record.payload.clone(),
        };
        match pool.publish(&event, fanout.max(1)).await {
            Ok(delivered) => {
                self.state.remove_outbox(&record.peer_id, &record.msg_id);
                delivered
            }
            Err(_) => 0,
        }
    }

    /// Publish the signed bundle to our bundle mailbox (throttled).
    ///
    /// Short invites carry only the peer id, so the bundle must be
    /// fetchable from the relays while we are online. Live-only carriers
    /// (MQTT) keep nothing, hence the periodic re-publish; store-and-
    /// forward relays keep it for their TTL anyway.
    async fn publish_bundle(&mut self, pool: &RelayPool) -> Result<()> {
        let now = now_unix();
        if now.saturating_sub(self.last_bundle_publish) < BUNDLE_PUBLISH_INTERVAL {
            return Ok(());
        }
        let peer_id = self.state.peer_id()?;
        let mailbox = mailbox::bundle_mailbox_public(&peer_id);
        let payload = seal::seal(&mailbox, &self.state.bundle()?.to_bytes())?;
        let event = RelayEvent {
            mailbox,
            created_at: now,
            expires_at: now.saturating_add(MESSAGE_TTL_SECONDS),
            payload,
        };
        if pool.publish(&event, DEFAULT_FANOUT).await.is_ok() {
            self.last_bundle_publish = now;
        }
        Ok(())
    }

    /// Receive and decrypt available events, returning after `idle` with no
    /// new events.
    ///
    /// Queued outgoing events are retried first, and every newly decrypted
    /// message is acknowledged back to the sender.
    pub async fn listen_once(
        &mut self,
        pool: &RelayPool,
        idle: Duration,
        since: u64,
    ) -> Result<ListenOutcome> {
        let _ = self.flush_due_outbox(pool, DEFAULT_FANOUT).await?;
        let _ = self.publish_bundle(pool).await;
        let mut outcome = ListenOutcome::default();
        let mut pending_acks: Vec<([u8; 32], [u8; 16])> = Vec::new();
        let mut advanced = false;

        loop {
            let (mailboxes, map, resume) = self.subscriptions()?;
            if mailboxes.is_empty() {
                break;
            }

            let effective_since = since.max(resume);
            let mut stream = pool.subscribe_all_many(&mailboxes, effective_since).await?;
            let mut restart = false;

            loop {
                match tokio::time::timeout(idle, stream.next()).await {
                    Err(_) => break,
                    Ok(None) => break,
                    // Resilient pool streams reconnect internally. If a
                    // non-recoverable error surfaces, rebuild the subscription
                    // instead of failing the whole listen pass.
                    Ok(Some(Err(_))) => break,
                    Ok(Some(Ok(event))) => {
                        let epoch = match map.get(&event.mailbox) {
                            Some(MailboxRef::Inbox { epoch, .. }) => Some(*epoch),
                            _ => None,
                        };
                        self.state
                            .advance_cursor(event.mailbox, epoch, event.created_at);
                        advanced = true;

                        match self.process_event(&map, &event).await? {
                            Processed::Ignored => {}
                            Processed::Message(message) => {
                                let target = (message.peer_id, message.msg_id);
                                if !pending_acks.contains(&target) {
                                    pending_acks.push(target);
                                }
                                outcome.messages.push(message);
                            }
                            Processed::Ack(ack) => outcome.acks.push(ack),
                            Processed::ContactAdded(peer_id) => {
                                // New contact means new inbox mailboxes: rebuild
                                // the subscription and replay from the relay.
                                outcome.added_contacts.push(peer_id);
                                restart = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !restart {
                break;
            }
        }

        if advanced {
            let epoch = mailbox::epoch_of(now_unix());
            self.state.prune_cursors(epoch.saturating_sub(2));
            self.save()?;
        }

        // WebRTC pass: publish queued signaling (answers, ICE
        // candidates) and poll data channels for direct deliveries.
        if self.webrtc_enabled {
            self.webrtc_pass(pool, &mut outcome, &mut pending_acks)
                .await?;
        }

        for (peer_id, msg_id) in pending_acks {
            self.send_ack(&peer_id, &msg_id, pool, DEFAULT_FANOUT)
                .await?;
        }

        Ok(outcome)
    }

    /// One WebRTC sweep: flush signaling, poll data channels.
    async fn webrtc_pass(
        &mut self,
        pool: &RelayPool,
        outcome: &mut ListenOutcome,
        pending_acks: &mut Vec<([u8; 32], [u8; 16])>,
    ) -> Result<()> {
        if self.webrtc_sessions.is_empty() {
            return Ok(());
        }
        let (_, map, _) = self.subscriptions()?;
        let peers: Vec<[u8; 32]> = self.webrtc_sessions.keys().copied().collect();
        for peer_id in peers {
            // Flush queued signaling (answers + gathered candidates).
            let outbound: Vec<Signaling> = match self.webrtc_sessions.get(&peer_id) {
                Some(session) => session.take_outbound(),
                None => Vec::new(),
            };
            for signaling in outbound {
                self.publish_signaling(pool, &peer_id, &signaling).await;
            }
            // Re-offer when an initiator is still waiting for an answer.
            let now = now_unix();
            let needs_offer = self
                .webrtc_sessions
                .get(&peer_id)
                .map(|session| session.needs_offer(now))
                .unwrap_or(false);
            if needs_offer {
                if let Some(session) = self.webrtc_sessions.get_mut(&peer_id) {
                    if let Ok(offer) = session.offer().await {
                        self.publish_signaling(pool, &peer_id, &offer).await;
                    }
                }
            }
            // Poll the data channel for direct deliveries.
            let incoming = match self.webrtc_sessions.get(&peer_id) {
                Some(session) => {
                    session
                        .poll_message(Duration::from_millis(10))
                        .await
                }
                None => None,
            };
            if let Some(bytes) = incoming {
                if let Ok(event) = serde_json::from_slice::<RelayEvent>(&bytes) {
                    match self.process_event(&map, &event).await? {
                        Processed::Ignored => {}
                        Processed::Message(message) => {
                            let target = (message.peer_id, message.msg_id);
                            if !pending_acks.contains(&target) {
                                pending_acks.push(target);
                            }
                            outcome.messages.push(message);
                        }
                        Processed::Ack(ack) => outcome.acks.push(ack),
                        Processed::ContactAdded(peer_id) => {
                            outcome.added_contacts.push(peer_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Encrypt and queue a delivery acknowledgement.
    async fn send_ack(
        &mut self,
        peer_id: &[u8; 32],
        acked_msg_id: &[u8; 16],
        pool: &RelayPool,
        fanout: usize,
    ) -> Result<()> {
        let record = self.seal_body(
            peer_id,
            &Body::Ack(AckBody::new(*acked_msg_id)),
            MESSAGE_TTL_SECONDS,
        )?;
        self.state.enqueue_outbox(record.clone());
        self.save()?;
        let _ = self.try_deliver(&record, pool, fanout).await;
        self.save()?;
        Ok(())
    }

    fn subscriptions(&self) -> Result<(Vec<[u8; 32]>, SubscriptionMap, u64)> {
        let me = self.state.peer_id()?;
        let mut map = HashMap::new();

        // Every prekey keeps its own handshake mailbox until it is retired.
        for index in 0..self.state.prekey_count() {
            let prekey = self.state.prekey_at(index)?;
            let created_at = self.state.prekey_created_at(index)?;
            map.insert(
                prekey.signed_prekey_public(),
                MailboxRef::Handshake {
                    prekey: index,
                    created_at,
                    secret: prekey.signed_prekey.to_bytes(),
                },
            );
        }

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
                            epoch: current,
                            secret: chain.slot_secret(current, index),
                        },
                    );
                }
            }
        }

        // WebRTC signaling mailbox (opt-in): our own mailbox, signaling
        // from any contact arrives here; the sender is inside the
        // sealed signaling message.
        if self.webrtc_enabled {
            map.insert(
                mailbox::signaling_mailbox_public(&me),
                MailboxRef::Signaling {
                    peer_id: me,
                    secret: mailbox::signaling_mailbox_secret(&me),
                },
            );
        }

        // Replay only what may have been produced after a mailbox or session
        // existed, then from the newest cursor for mailboxes already seen.
        // Using the minimum across mailboxes is required because the relay's
        // `since` is global for the whole subscription.
        let mut resume = u64::MAX;
        for (mailbox, reference) in &map {
            let floor = match reference {
                MailboxRef::Handshake { created_at, .. } => *created_at,
                MailboxRef::Signaling { peer_id, .. } => self
                    .state
                    .contact(peer_id)
                    .map(|contact| contact.created_at)
                    .unwrap_or(0),
                MailboxRef::Inbox { epoch, peer_id, .. } => {
                    let epoch_start = u64::from(*epoch) * mailbox::EPOCH_SECONDS;
                    let contact_start = self
                        .state
                        .contact(peer_id)
                        .map(|contact| contact.created_at)
                        .unwrap_or(0);
                    epoch_start.max(contact_start)
                }
            };
            // `since` is exclusive, so start one second before the earliest
            // possible event (prekey/contact creation or epoch boundary).
            let base = floor.saturating_sub(1);
            let cursor = self.state.cursor(mailbox).map_or(base, |value| value.max(base));
            resume = resume.min(cursor);
        }
        if resume == u64::MAX {
            resume = 0;
        }

        let mailboxes = map.keys().copied().collect();
        Ok((mailboxes, map, resume))
    }

    async fn process_event(
        &mut self,
        map: &HashMap<[u8; 32], MailboxRef>,
        event: &RelayEvent,
    ) -> Result<Processed> {
        match map.get(&event.mailbox).cloned() {
            Some(MailboxRef::Handshake { prekey, secret, .. }) => {
                self.process_handshake(prekey, &secret, &event.payload)
            }
            Some(MailboxRef::Inbox {
                peer_id, secret, ..
            }) => self.process_text(&peer_id, &secret, &event.payload),
            Some(MailboxRef::Signaling { peer_id, secret }) => {
                self.process_signaling(&peer_id, &secret, &event.payload).await
            }
            None => Ok(Processed::Ignored),
        }
    }

    /// Handle one WebRTC signaling payload sealed to our signaling mailbox.
    async fn process_signaling(
        &mut self,
        peer_id: &[u8; 32],
        secret: &[u8; 32],
        payload: &[u8],
    ) -> Result<Processed> {
        if !self.webrtc_enabled {
            return Ok(Processed::Ignored);
        }
        let plaintext = match seal::open(secret, payload) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(Processed::Ignored),
        };
        let signaling: Signaling = match serde_json::from_slice(&plaintext) {
            Ok(signaling) => signaling,
            Err(_) => return Ok(Processed::Ignored),
        };
        // `peer_id` here is our own id (the mailbox owner); the actual
        // sender is stamped inside the signaling message.
        let sender = signaling.from();
        if sender == *peer_id {
            return Ok(Processed::Ignored);
        }
        // Responder sessions are created on demand.
        if !self.webrtc_sessions.contains_key(&sender) {
            let own = match self.state.peer_id() {
                Ok(own) => own,
                Err(_) => return Ok(Processed::Ignored),
            };
            match WebRtcSession::new(false, own).await {
                Ok(session) => {
                    self.webrtc_sessions.insert(sender, session);
                }
                Err(_) => return Ok(Processed::Ignored),
            }
        }
        let Some(session) = self.webrtc_sessions.get_mut(&sender) else {
            return Ok(Processed::Ignored);
        };
        if let Ok(Some(response)) = session.apply(&signaling).await {
            session.push_outbound(response);
        }
        Ok(Processed::Ignored)
    }

    fn process_handshake(
        &mut self,
        prekey_index: usize,
        secret: &[u8; 32],
        payload: &[u8],
    ) -> Result<Processed> {
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

        let prekeys = match self.state.prekey_at(prekey_index) {
            Ok(prekeys) => prekeys,
            Err(_) => return Ok(Processed::Ignored),
        };
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
        Ok(Processed::ContactAdded(peer_id))
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
        let body = match Body::decode(body_bytes) {
            Ok(body) => body,
            Err(_) => return Ok(Processed::Ignored),
        };

        // A successful ratchet decrypt proves the peer holds the private
        // identity key behind the pinned public keys.
        let msg_id = body.msg_id();
        let already_seen = self.state.seen(peer_id, &msg_id);
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
        self.state.mark_seen(peer_id, &msg_id);

        let processed = match body {
            Body::Text(body) => Processed::Message(ReceivedMessage {
                peer_id: *peer_id,
                msg_id: body.msg_id,
                timestamp_ms: body.timestamp_ms,
                text: body.text,
            }),
            Body::Ack(ack) => {
                self.state.mark_acked(peer_id, &ack.acked_msg_id);
                Processed::Ack(ReceivedAck {
                    peer_id: *peer_id,
                    acked_msg_id: ack.acked_msg_id,
                })
            }
        };

        self.save()?;
        Ok(processed)
    }
}

/// Relay hints worth embedding in an invite: everything except the
/// built-in defaults every client already knows.
fn invite_hints(relays: &[String]) -> Vec<String> {
    let defaults = oc_transport::relay_list::default_relays().unwrap_or_default();
    relays
        .iter()
        .filter(|relay| !defaults.contains(relay))
        .cloned()
        .collect()
}

/// Fetch a signed bundle from a peer's bundle mailbox (short invites).
///
/// The bundle is self-signed by the peer's identity key, so the fetched
/// bytes are verified before use: a relay or broker cannot substitute a
/// different bundle without the identity private key.
async fn fetch_bundle(
    pool: &RelayPool,
    peer_id: &[u8; 32],
) -> Result<oc_core::x3dh::PrekeyBundle> {
    let mailbox = mailbox::bundle_mailbox_public(peer_id);
    let secret = mailbox::bundle_mailbox_secret(peer_id);
    let mut stream = pool.subscribe_all_many(&[mailbox], 0).await?;
    let deadline = tokio::time::Instant::now() + BUNDLE_FETCH_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Invite);
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(event))) if event.mailbox == mailbox => {
                let Ok(plaintext) = seal::open(&secret, &event.payload) else {
                    continue;
                };
                let Ok(bundle) = oc_core::x3dh::PrekeyBundle::from_bytes(&plaintext) else {
                    continue;
                };
                if bundle.verify().is_ok() && bundle.identity.peer_id() == *peer_id {
                    return Ok(bundle);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) | Ok(None) => return Err(Error::Invite),
            Err(_) => return Err(Error::Invite),
        }
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
    fn invite_hints_skip_builtin_defaults() {
        let defaults = oc_transport::relay_list::default_relays().unwrap();
        assert!(!defaults.is_empty(), "default list should be filled");
        // All-default relays produce no hints (short invite).
        assert!(invite_hints(&defaults).is_empty());
        // Custom relays are kept.
        let mut mixed = defaults.clone();
        mixed.push("https://relay.example".to_string());
        assert_eq!(invite_hints(&mixed), vec!["https://relay.example"]);
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
