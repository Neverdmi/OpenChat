//! Desktop UI state and the background protocol worker.
//!
//! The egui rendering lives in [`OpenChatApp::update`]; everything that
//! can be tested without a window (event application, contact snapshots,
//! CLI-mode detection helpers) is kept in plain structs below.
//!
//! Message history is session-only by design: the encrypted client state
//! stores no plaintext, so the desktop view shows what arrived while the
//! app is open (plus relay replay on start), exactly like the CLI.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use oc_client::invite::short_peer_id;
use oc_client::{Client, ListenOutcome, StateStore};
use oc_transport::RelayPool;

/// One contact as shown in the sidebar.
#[derive(Debug, Clone)]
pub struct ContactView {
    /// Peer id.
    pub peer_id: [u8; 32],
    /// Short display id.
    pub short: String,
    /// Whether the peer proved its identity keys (TOFU verified).
    pub verified: bool,
    /// Safety number, hex chunks.
    pub safety: String,
}

/// One line in the conversation view.
#[derive(Debug, Clone)]
pub struct ChatLine {
    /// Display name of the sender (`me` for outgoing).
    pub author: String,
    /// Message text.
    pub text: String,
    /// Whether this line is an outgoing message.
    pub outgoing: bool,
}

/// Events flowing from the worker thread to the UI thread.
#[derive(Debug)]
pub enum UiEvent {
    /// Fresh contact/invite/outbox snapshot.
    Snapshot {
        /// Contacts in sidebar order.
        contacts: Vec<ContactView>,
        /// Our invite link.
        invite: String,
        /// Outgoing events still waiting for a relay.
        outbox_len: usize,
    },
    /// One receive pass finished.
    Outcome(ListenOutcome),
    /// A text message was handed to the outbox path.
    Sent {
        /// Whether it is still queued.
        queued: bool,
        /// Relays that accepted it.
        delivered: usize,
    },
    /// An invite was accepted and the handshake queued/published.
    Added {
        /// Short peer id.
        peer: String,
        /// Whether the handshake is still queued.
        queued: bool,
    },
    /// Outbox flush result.
    Flushed(usize),
    /// Human-readable worker error.
    Error(String),
}

/// Commands flowing from the UI thread to the worker thread.
pub enum WorkerCommand {
    /// Send text to a peer.
    Send {
        /// Recipient.
        peer: [u8; 32],
        /// Text.
        text: String,
    },
    /// Add a contact from an invite link.
    AddInvite(String),
    /// Retry the whole outbox now.
    Flush,
}

/// Handles to the running worker thread.
pub struct Worker {
    /// Command channel (UI -> worker).
    pub commands: mpsc::Sender<WorkerCommand>,
    /// Event channel (worker -> UI).
    pub events: mpsc::Receiver<UiEvent>,
}

/// Application state for `eframe`.
pub struct OpenChatApp {
    /// Encrypted-state directory (editable on the unlock screen).
    pub home: String,
    /// Passphrase (editable on the unlock screen).
    pub passphrase: String,
    /// Unlock/worker error to show.
    pub error: Option<String>,
    /// Worker handles once unlocked.
    pub worker: Option<Worker>,
    /// Contacts from the last snapshot.
    pub contacts: Vec<ContactView>,
    /// Our invite link from the last snapshot.
    pub invite: String,
    /// Outbox size from the last snapshot.
    pub outbox_len: usize,
    /// Currently selected peer.
    pub selected: Option<[u8; 32]>,
    /// Conversation lines (session only).
    pub lines: Vec<ChatLine>,
    /// Draft message.
    pub input: String,
    /// Draft invite link.
    pub invite_input: String,
    /// Last status message.
    pub status: String,
}

impl OpenChatApp {
    /// Create the app on the unlock screen.
    pub fn new() -> Self {
        Self {
            home: default_home().to_string_lossy().into_owned(),
            passphrase: String::new(),
            error: None,
            worker: None,
            contacts: Vec::new(),
            invite: String::new(),
            outbox_len: 0,
            selected: None,
            lines: Vec::new(),
            input: String::new(),
            invite_input: String::new(),
            status: String::new(),
        }
    }

    /// Whether the unlock screen should be shown.
    pub fn is_locked(&self) -> bool {
        self.worker.is_none()
    }

    /// Whether a message can be sent right now.
    pub fn can_send(&self) -> bool {
        self.selected.is_some() && !self.input.trim().is_empty()
    }

    /// Short id of the selected peer, if any.
    pub fn selected_short(&self) -> Option<String> {
        self.selected.map(|peer_id| short_peer_id(&peer_id))
    }

    /// Apply one worker event to the UI state.
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Snapshot {
                contacts,
                invite,
                outbox_len,
            } => {
                self.contacts = contacts;
                self.invite = invite;
                self.outbox_len = outbox_len;
            }
            UiEvent::Outcome(outcome) => self.apply_outcome(&outcome),
            UiEvent::Sent { queued, delivered } => {
                self.status = if queued {
                    "queued (relay unavailable, will retry)".to_string()
                } else {
                    format!("sent via {delivered} relay(s)")
                };
            }
            UiEvent::Added { peer, queued } => {
                self.status = if queued {
                    format!("handshake with {peer} queued")
                } else {
                    format!("handshake with {peer} sent")
                };
            }
            UiEvent::Flushed(delivered) => {
                self.status = format!("flushed: {delivered} delivered");
            }
            UiEvent::Error(message) => {
                self.error = Some(message);
            }
        }
    }

    /// Apply one receive pass: messages, acks and new contacts.
    pub fn apply_outcome(&mut self, outcome: &ListenOutcome) {
        for peer_id in &outcome.added_contacts {
            self.lines.push(ChatLine {
                author: "system".to_string(),
                text: format!("new contact: {}", short_peer_id(peer_id)),
                outgoing: false,
            });
        }
        for message in &outcome.messages {
            self.lines.push(ChatLine {
                author: short_peer_id(&message.peer_id),
                text: message.text.clone(),
                outgoing: false,
            });
        }
        for ack in &outcome.acks {
            self.lines.push(ChatLine {
                author: "system".to_string(),
                text: format!(
                    "ack: {} delivered {}",
                    short_peer_id(&ack.peer_id),
                    hex::encode(ack.acked_msg_id)
                ),
                outgoing: false,
            });
        }
    }

    /// Queue the draft input as an outgoing message.
    pub fn queue_send(&mut self) {
        let Some(peer) = self.selected else {
            self.status = "select a contact first".to_string();
            return;
        };
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return;
        }
        if let Some(worker) = &self.worker {
            let _ = worker
                .commands
                .send(WorkerCommand::Send { peer, text: text.clone() });
            self.lines.push(ChatLine {
                author: "me".to_string(),
                text,
                outgoing: true,
            });
            self.input.clear();
        }
    }

    /// Drain all pending worker events.
    pub fn poll_events(&mut self) {
        let events: Vec<UiEvent> = match &self.worker {
            Some(worker) => worker.events.try_iter().collect(),
            None => Vec::new(),
        };
        for event in events {
            self.apply(event);
        }
    }

    /// Try to unlock the state and start the worker thread.
    pub fn unlock(&mut self) {
        let home = PathBuf::from(self.home.trim());
        if !StateStore::exists(&home) {
            self.error = Some(format!(
                "no state at {} — create one first with: oc init",
                StateStore::path_in(&home).display()
            ));
            return;
        }
        let result = (|| -> Result<Worker, String> {
            let store = StateStore::open(&home, &self.passphrase)
                .map_err(|error| format!("open state: {error:#}"))?;
            let client = Client::open(store)
                .map_err(|error| format!("open client: {error:#}"))?;
            Ok(spawn_worker(client))
        })();
        match result {
            Ok(worker) => {
                self.worker = Some(worker);
                self.error = None;
                self.status = "unlocked".to_string();
            }
            Err(message) => {
                self.error = Some(message);
            }
        }
    }
}

impl Default for OpenChatApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a safety number as hex chunks, like the CLI.
pub fn format_safety(bytes: &[u8; 32]) -> String {
    bytes
        .chunks(4)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Default state directory (`~/.openchat`), mirroring the CLI.
pub fn default_home() -> PathBuf {
    if let Some(home) = std::env::var_os("OPENCHAT_HOME") {
        return PathBuf::from(home);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".openchat");
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(home).join(".openchat");
    }
    PathBuf::from(".openchat")
}

fn build_pool(relays: &[String]) -> Result<RelayPool, String> {
    if relays.is_empty() {
        return Err("no relays configured".to_string());
    }
    RelayPool::from_urls(relays.iter().cloned())
        .map_err(|error| format!("invalid relay list: {error:#}"))
}

fn snapshot(client: &Client) -> UiEvent {
    UiEvent::Snapshot {
        contacts: client
            .contacts()
            .iter()
            .map(|contact| ContactView {
                peer_id: contact.peer_id,
                short: short_peer_id(&contact.peer_id),
                verified: contact.verified,
                safety: format_safety(&contact.safety_number),
            })
            .collect(),
        invite: client.invite().unwrap_or_default(),
        outbox_len: client.outbox().len(),
    }
}

/// Spawn the background thread that owns the `Client` and the pool.
pub fn spawn_worker(client: Client) -> Worker {
    let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
    let (event_tx, event_rx) = mpsc::channel::<UiEvent>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for worker");
        runtime.block_on(worker_loop(client, command_rx, event_tx));
    });
    Worker {
        commands: command_tx,
        events: event_rx,
    }
}

async fn worker_loop(
    mut client: Client,
    commands: mpsc::Receiver<WorkerCommand>,
    events: mpsc::Sender<UiEvent>,
) {
    let mut pool = match build_pool(client.relays()) {
        Ok(pool) => pool,
        Err(message) => {
            let _ = events.send(UiEvent::Error(message));
            return;
        }
    };
    let _ = events.send(snapshot(&client));

    loop {
        // Handle every queued command before the next receive pass.
        while let Ok(command) = commands.try_recv() {
            match command {
                WorkerCommand::Send { peer, text } => {
                    match client.send_text(&peer, &text, &pool, 3).await {
                        Ok(sent) => {
                            let _ = events.send(UiEvent::Sent {
                                queued: sent.queued,
                                delivered: sent.delivered,
                            });
                        }
                        Err(error) => {
                            let _ = events.send(UiEvent::Error(format!("send: {error:#}")));
                        }
                    }
                }
                WorkerCommand::AddInvite(link) => {
                    match client.add_invite(&link, &pool, 3).await {
                        Ok(summary) => {
                            // The invite may carry new relay hints; rebuild
                            // the pool so they are used from now on.
                            if let Ok(new_pool) = build_pool(client.relays()) {
                                pool = new_pool;
                            }
                            let _ = events.send(UiEvent::Added {
                                peer: short_peer_id(&summary.peer_id),
                                queued: summary.queued,
                            });
                        }
                        Err(error) => {
                            let _ = events.send(UiEvent::Error(format!("add: {error:#}")));
                        }
                    }
                }
                WorkerCommand::Flush => match client.flush_outbox(&pool, 3).await {
                    Ok(delivered) => {
                        let _ = events.send(UiEvent::Flushed(delivered));
                    }
                    Err(error) => {
                        let _ = events.send(UiEvent::Error(format!("flush: {error:#}")));
                    }
                },
            }
            let _ = events.send(snapshot(&client));
        }

        match client.listen_once(&pool, Duration::from_secs(1), 0).await {
            Ok(outcome) => {
                let _ = events.send(UiEvent::Outcome(outcome));
                let _ = events.send(snapshot(&client));
            }
            Err(error) => {
                let _ = events.send(UiEvent::Error(format!("listen: {error:#}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oc_client::{ReceivedAck, ReceivedMessage};

    #[test]
    fn apply_outcome_appends_messages_and_acks() {
        let mut app = OpenChatApp::new();
        let outcome = ListenOutcome {
            messages: vec![ReceivedMessage {
                peer_id: [7u8; 32],
                msg_id: [1u8; 16],
                timestamp_ms: 0,
                text: "hello".to_string(),
            }],
            acks: vec![ReceivedAck {
                peer_id: [7u8; 32],
                acked_msg_id: [1u8; 16],
            }],
            added_contacts: vec![[9u8; 32]],
        };
        app.apply_outcome(&outcome);
        assert_eq!(app.lines.len(), 3);
        assert_eq!(app.lines[0].author, "system");
        assert_eq!(app.lines[1].text, "hello");
        assert!(app.lines[2].text.starts_with("ack: "));
    }

    #[test]
    fn can_send_requires_peer_and_text() {
        let mut app = OpenChatApp::new();
        app.input = "hi".to_string();
        assert!(!app.can_send());
        app.selected = Some([1u8; 32]);
        assert!(app.can_send());
        app.input = "   ".to_string();
        assert!(!app.can_send());
    }

    #[test]
    fn send_without_worker_or_peer_is_safe() {
        let mut app = OpenChatApp::new();
        app.input = "hi".to_string();
        app.queue_send();
        assert_eq!(app.status, "select a contact first");
        assert_eq!(app.input, "hi");
    }

    #[test]
    fn safety_formatting_is_chunked_hex() {
        let formatted = format_safety(&[0xABu8; 32]);
        assert_eq!(formatted.split(' ').count(), 8);
        assert!(formatted.starts_with("abababab"));
    }

    #[test]
    fn is_locked_until_worker_starts() {
        let app = OpenChatApp::new();
        assert!(app.is_locked());
        assert_eq!(app.selected_short(), None);
    }
}
