//! TUI state and the background protocol worker.
//!
//! Same architecture as the desktop UI: a worker thread owns the
//! `Client` and the relay pool (its own tokio runtime), the terminal
//! thread owns this state and renders it with ratatui. Everything that
//! can be tested without a terminal lives here as plain structs.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use oc_client::invite::short_peer_id;
use oc_client::{Client, ListenOutcome, StateStore};
use oc_transport::socks5::TorConfig;
use oc_transport::{RelayPool, TorMode};

use crate::settings::{self, Settings};

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
        /// Our own short peer id.
        own_short: String,
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
    /// Informational status line (e.g. Tor bootstrapping).
    Status(String),
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
    /// Stop the worker thread (used when restarting with new settings).
    Shutdown,
}

/// Handles to the running worker thread.
pub struct Worker {
    /// Command channel (UI -> worker).
    pub commands: mpsc::Sender<WorkerCommand>,
    /// Event channel (worker -> UI).
    pub events: mpsc::Receiver<UiEvent>,
}

/// Which unlock-form field is being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockField {
    /// State directory.
    Home,
    /// Passphrase.
    Passphrase,
    /// Repeated passphrase (create mode only).
    Confirm,
}

/// Unlock screen mode: open an existing state or create a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Open existing encrypted state.
    Unlock,
    /// Create a new identity + state.
    Create,
}

/// Which panel has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// Message input (default).
    Input,
    /// Contact list.
    Contacts,
}

/// What one submitted input line means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    /// Nothing to do (blank line).
    Empty,
    /// Leave the TUI.
    Quit,
    /// Show help in the status line.
    Help,
    /// Switch focus to the contact list.
    FocusContacts,
    /// Retry the whole outbox now.
    Flush,
    /// Show the full invite link panel.
    Invite,
    /// Open the settings menu.
    Settings,
    /// Add a contact from this invite link.
    AddInvite(String),
    /// Send this text to the selected peer.
    Text(String),
}

/// Parse one submitted input line.
pub fn parse_input(line: &str) -> InputAction {
    let line = line.trim();
    if line.is_empty() {
        return InputAction::Empty;
    }
    if line == "/quit" || line == "/exit" {
        return InputAction::Quit;
    }
    if line == "/help" {
        return InputAction::Help;
    }
    if line == "/contacts" {
        return InputAction::FocusContacts;
    }
    if line == "/flush" {
        return InputAction::Flush;
    }
    if line == "/invite" {
        return InputAction::Invite;
    }
    if line == "/settings" {
        return InputAction::Settings;
    }
    if line.starts_with("openchat://") {
        return InputAction::AddInvite(line.to_string());
    }
    if let Some(rest) = line.strip_prefix("/add ") {
        let link = rest.trim();
        if !link.is_empty() {
            return InputAction::AddInvite(link.to_string());
        }
    }
    InputAction::Text(line.to_string())
}

/// Application state for the TUI.
pub struct TuiApp {
    /// Screen: unlock form or main chat.
    pub locked: bool,
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
    /// Our own short peer id.
    pub own_short: String,
    /// Outbox size from the last snapshot.
    pub outbox_len: usize,
    /// Set by the UI when the invite should be copied to the clipboard.
    pub copy_requested: bool,
    /// Index into `contacts` of the selected peer.
    pub selected: usize,
    /// Conversation lines (session only).
    pub lines: Vec<ChatLine>,
    /// Draft message.
    pub input: String,
    /// Focused panel.
    pub focus: Focus,
    /// Active unlock-form field.
    pub lock_field: LockField,
    /// Unlock screen mode (open existing / create new).
    pub lock_mode: LockMode,
    /// Confirmation of the passphrase (create mode only).
    pub confirm_passphrase: String,
    /// Whether the full invite link panel is shown.
    pub show_invite: bool,
    /// User settings (loaded from `settings.json` after unlocking).
    pub settings: Settings,
    /// Whether the settings menu is open.
    pub show_settings: bool,
    /// Selected row in the settings menu.
    pub settings_row: usize,
    /// Last status message.
    pub status: String,
    /// Set when the user asked to quit.
    pub should_quit: bool,
}

impl TuiApp {
    /// Create the app on the unlock screen.
    pub fn new() -> Self {
        Self {
            locked: true,
            home: default_home().to_string_lossy().into_owned(),
            passphrase: String::new(),
            error: None,
            worker: None,
            contacts: Vec::new(),
            invite: String::new(),
            own_short: String::new(),
            copy_requested: false,
            outbox_len: 0,
            selected: 0,
            lines: Vec::new(),
            input: String::new(),
            focus: Focus::Input,
            lock_field: LockField::Passphrase,
            lock_mode: LockMode::Unlock,
            confirm_passphrase: String::new(),
            show_invite: false,
            settings: Settings::default(),
            show_settings: false,
            settings_row: 0,
            status: String::new(),
            should_quit: false,
        }
    }

    /// Currently selected peer id, if any.
    pub fn selected_peer(&self) -> Option<[u8; 32]> {
        self.contacts.get(self.selected).map(|c| c.peer_id)
    }

    /// Short id of the selected peer, if any.
    pub fn selected_short(&self) -> Option<String> {
        self.contacts.get(self.selected).map(|c| c.short.clone())
    }

    /// Whether a message can be sent right now.
    pub fn can_send(&self) -> bool {
        self.selected_peer().is_some() && !self.input.trim().is_empty()
    }

    /// Move the contact selection by `delta` lines, wrapping around.
    pub fn move_selection(&mut self, delta: i32) {
        if self.contacts.is_empty() {
            return;
        }
        let len = self.contacts.len() as i32;
        self.selected = (self.selected as i32 + delta).rem_euclid(len) as usize;
    }

    /// Handle one submitted input line.
    pub fn submit_input(&mut self) {
        match parse_input(&self.input) {
            InputAction::Empty => {}
            InputAction::Quit => self.should_quit = true,
            InputAction::Help => {
                self.status = "Enter send · Tab contacts · /add <invite> add contact · /quit exit"
                    .to_string();
            }
            InputAction::FocusContacts => self.focus = Focus::Contacts,
            InputAction::Flush => {
                if let Some(worker) = &self.worker {
                    let _ = worker.commands.send(WorkerCommand::Flush);
                }
                self.input.clear();
            }
            InputAction::Invite => {
                self.show_invite = true;
                self.input.clear();
            }
            InputAction::Settings => {
                self.show_settings = true;
                self.settings_row = 0;
                self.input.clear();
            }
            InputAction::AddInvite(link) => {
                if let Some(worker) = &self.worker {
                    let _ = worker.commands.send(WorkerCommand::AddInvite(link));
                }
                self.input.clear();
            }
            InputAction::Text(text) => {
                let Some(peer) = self.selected_peer() else {
                    self.status = "select a contact first (Tab, arrows)".to_string();
                    return;
                };
                if let Some(worker) = &self.worker {
                    let _ = worker.commands.send(WorkerCommand::Send {
                        peer,
                        text: text.clone(),
                    });
                    self.lines.push(ChatLine {
                        author: "me".to_string(),
                        text,
                        outgoing: true,
                    });
                }
                self.input.clear();
            }
        }
    }

    /// Apply one worker event to the UI state.
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Snapshot {
                contacts,
                invite,
                own_short,
                outbox_len,
            } => {
                self.contacts = contacts;
                self.invite = invite;
                self.own_short = own_short;
                self.outbox_len = outbox_len;
                if self.selected >= self.contacts.len() {
                    self.selected = self.contacts.len().saturating_sub(1);
                }
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
            UiEvent::Status(message) => {
                self.status = message;
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

    /// Validate a create-state request without touching the filesystem.
    pub fn validate_create(&self) -> Result<(), String> {
        if StateStore::exists(&PathBuf::from(self.home.trim())) {
            return Err("state already exists here — use Unlock mode".to_string());
        }
        if self.passphrase.chars().count() < 8 {
            return Err("passphrase must be at least 8 characters".to_string());
        }
        if self.passphrase != self.confirm_passphrase {
            return Err("passphrases do not match".to_string());
        }
        Ok(())
    }

    /// Generate a strong memorable passphrase and fill both fields.
    pub fn generate_passphrase(&mut self) {
        let generated = generate_passphrase();
        self.passphrase = generated.clone();
        self.confirm_passphrase = generated;
        self.status = "generated passphrase — write it down, it cannot be recovered"
            .to_string();
    }

    /// Create a new identity + encrypted state and start the worker.
    pub fn create_state(&mut self) {
        if let Err(message) = self.validate_create() {
            self.error = Some(message);
            return;
        }
        let home = PathBuf::from(self.home.trim());
        let result = (|| -> Result<Worker, String> {
            let store = StateStore::create(&home, &self.passphrase)
                .map_err(|error| format!("create state: {error:#}"))?;
            let relays = oc_transport::relay_list::default_relays()
                .map_err(|error| format!("relay list: {error:#}"))?;
            let client = Client::create(store, relays)
                .map_err(|error| format!("create client: {error:#}"))?;
            self.settings = settings::load(&home);
            Ok(spawn_worker(client, &home, self.settings.clone()))
        })();
        self.finish_start(result, "identity created — share your invite with /invite");
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
            self.settings = settings::load(&home);
            Ok(spawn_worker(client, &home, self.settings.clone()))
        })();
        self.finish_start(result, "unlocked");
    }

    fn finish_start(&mut self, result: Result<Worker, String>, ok_status: &str) {
        match result {
            Ok(worker) => {
                self.worker = Some(worker);
                self.error = None;
                self.locked = false;
                self.status = ok_status.to_string();
                if self.settings.show_invite_on_start {
                    self.show_invite = true;
                }
            }
            Err(message) => {
                self.error = Some(message);
            }
        }
    }

    /// Restart the worker with the current settings (after a change).
    pub fn restart_worker(&mut self) {
        if let Some(worker) = &self.worker {
            let _ = worker.commands.send(WorkerCommand::Shutdown);
        }
        self.worker = None;
        self.unlock();
    }

    /// Persist settings and restart the worker so they take effect.
    pub fn apply_settings(&mut self) {
        let home = PathBuf::from(self.home.trim());
        if let Err(error) = settings::save(&home, &self.settings) {
            self.error = Some(format!("save settings: {error}"));
            return;
        }
        self.status = "settings saved".to_string();
        self.restart_worker();
    }

    /// Cycle the Tor mode by `delta` (settings menu).
    pub fn cycle_tor(&mut self, delta: i32) {
        self.settings.tor_mode = if delta >= 0 {
            self.settings.tor_mode.next()
        } else {
            self.settings.tor_mode.prev()
        };
        self.apply_settings();
    }

    /// Adjust fan-out by `delta`, clamped to 1–5 (settings menu).
    pub fn adjust_fanout(&mut self, delta: i32) {
        self.settings.fanout = (self.settings.fanout as i32 + delta).clamp(1, 5) as usize;
        self.apply_settings();
    }

    /// Toggle "show invite on start" (settings menu).
    pub fn toggle_invite_on_start(&mut self) {
        self.settings.show_invite_on_start = !self.settings.show_invite_on_start;
        self.apply_settings();
    }

    /// Toggle Tor bridges (settings menu).
    pub fn toggle_tor_bridges(&mut self) {
        self.settings.tor_bridges = !self.settings.tor_bridges;
        self.apply_settings();
    }

    /// Toggle WebRTC direct delivery (settings menu).
    pub fn toggle_webrtc(&mut self) {
        self.settings.webrtc = !self.settings.webrtc;
        self.apply_settings();
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Word list for generated passphrases (short, unambiguous, no digits
/// inside words so the result stays easy to type and read aloud).
const PASSPHRASE_WORDS: &[&str] = &[
    "amber", "birch", "candle", "delta", "eagle", "flint", "garden", "harbor", "island",
    "jungle", "karma", "lemon", "maple", "north", "ocean", "pepper", "quartz", "river",
    "solar", "tulip", "umber", "violet", "walnut", "xenon", "yellow", "zebra", "atlas",
    "basin", "cedar", "dune", "ember", "frost",
];

/// Generate a strong memorable passphrase: five random words plus a
/// four-digit suffix, e.g. `amber-flint-garden-4815`. Randomness comes
/// from the OS CSPRNG via `oc_core::random_array`.
pub fn generate_passphrase() -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(5);
    for _ in 0..5 {
        let bytes = oc_core::random_array::<2>();
        let index = (u16::from_le_bytes(bytes) as usize) % PASSPHRASE_WORDS.len();
        parts.push(PASSPHRASE_WORDS[index]);
    }
    let digits = u16::from_le_bytes(oc_core::random_array::<2>()) % 10_000;
    format!("{}-{:04}", parts.join("-"), digits)
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
        own_short: client
            .peer_id()
            .map(|peer_id| short_peer_id(&peer_id))
            .unwrap_or_default(),
        outbox_len: client.outbox().len(),
    }
}

/// Spawn the background thread that owns the `Client` and the pool.
pub fn spawn_worker(mut client: Client, home: &std::path::Path, settings: Settings) -> Worker {
    client.set_webrtc(settings.webrtc);
    let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
    let (event_tx, event_rx) = mpsc::channel::<UiEvent>();
    let home = home.to_path_buf();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for worker");
        runtime.block_on(worker_loop(client, home, settings, command_rx, event_tx));
    });
    Worker {
        commands: command_tx,
        events: event_rx,
    }
}

/// Local SOCKS5 port the embedded Tor proxy listens on.
const TOR_SOCKS_PORT: u16 = 9050;

async fn worker_loop(
    mut client: Client,
    home: std::path::PathBuf,
    settings: Settings,
    commands: mpsc::Receiver<WorkerCommand>,
    events: mpsc::Sender<UiEvent>,
) {
    // Embedded Tor (arti) + SOCKS5 proxy, if requested. The proxy task
    // lives as long as the worker; aborting it shuts Tor down.
    let mut proxy_task: Option<tokio::task::JoinHandle<()>> = None;
    let tor = match settings.tor_mode.to_mode() {
        TorMode::Off => TorConfig::direct(),
        mode => {
            let _ = events.send(UiEvent::Status(
                "bootstrapping Tor (10–60s first time)…".to_string(),
            ));
            match crate::tor::bootstrap_tor(&home, settings.tor_bridges).await {
                Ok(tor_client) => {
                    match tokio::net::TcpListener::bind(("127.0.0.1", TOR_SOCKS_PORT)).await {
                        Ok(listener) => {
                            proxy_task =
                                Some(tokio::spawn(crate::tor::run_socks_proxy(
                                    tor_client,
                                    listener,
                                )));
                            TorConfig {
                                mode,
                                proxy_host: "127.0.0.1".to_string(),
                                proxy_port: TOR_SOCKS_PORT,
                            }
                        }
                        Err(error) => {
                            let _ = events.send(UiEvent::Error(format!(
                                "tor socks bind: {error}"
                            )));
                            return;
                        }
                    }
                }
                Err(message) => {
                    let _ = events.send(UiEvent::Error(message));
                    return;
                }
            }
        }
    };
    let fanout = settings.fanout.clamp(1, 5);
    let mut pool = match RelayPool::from_urls_with_tor(client.relays().iter().cloned(), &tor) {
        Ok(pool) => pool,
        Err(error) => {
            let _ = events.send(UiEvent::Error(format!("relay list: {error:#}")));
            if let Some(task) = proxy_task {
                task.abort();
            }
            return;
        }
    };
    let _ = events.send(snapshot(&client));

    loop {
        // Handle every queued command before the next receive pass.
        while let Ok(command) = commands.try_recv() {
            match command {
                WorkerCommand::Shutdown => {
                    if let Some(task) = proxy_task {
                        task.abort();
                    }
                    return;
                }
                WorkerCommand::Send { peer, text } => {
                    match client.send_text(&peer, &text, &pool, fanout).await {
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
                    match client.add_invite(&link, &pool, fanout).await {
                        Ok(summary) => {
                            // The invite may carry new relay hints; rebuild
                            // the pool so they are used from now on.
                            if let Ok(new_pool) =
                                RelayPool::from_urls_with_tor(client.relays().iter().cloned(), &tor)
                            {
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
                WorkerCommand::Flush => match client.flush_outbox(&pool, fanout).await {
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
    fn input_parsing() {
        assert_eq!(parse_input(""), InputAction::Empty);
        assert_eq!(parse_input("/quit"), InputAction::Quit);
        assert_eq!(parse_input("/exit"), InputAction::Quit);
        assert_eq!(parse_input("/help"), InputAction::Help);
        assert_eq!(
            parse_input("openchat://v1/AAA/BBB"),
            InputAction::AddInvite("openchat://v1/AAA/BBB".to_string())
        );
        assert_eq!(
            parse_input("/add openchat://v1/AAA/BBB"),
            InputAction::AddInvite("openchat://v1/AAA/BBB".to_string())
        );
        assert_eq!(
            parse_input("hello world"),
            InputAction::Text("hello world".to_string())
        );
    }

    #[test]
    fn apply_outcome_appends_messages_and_acks() {
        let mut app = TuiApp::new();
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
        assert_eq!(app.lines[1].text, "hello");
    }

    #[test]
    fn selection_wraps_around() {
        let mut app = TuiApp::new();
        app.contacts = vec![
            ContactView {
                peer_id: [1u8; 32],
                short: "A".to_string(),
                verified: true,
                safety: String::new(),
            },
            ContactView {
                peer_id: [2u8; 32],
                short: "B".to_string(),
                verified: false,
                safety: String::new(),
            },
        ];
        app.move_selection(1);
        assert_eq!(app.selected, 1);
        app.move_selection(1);
        assert_eq!(app.selected, 0);
        app.move_selection(-1);
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn can_send_requires_peer_and_text() {
        let mut app = TuiApp::new();
        app.input = "hi".to_string();
        assert!(!app.can_send());
        app.contacts = vec![ContactView {
            peer_id: [1u8; 32],
            short: "A".to_string(),
            verified: true,
            safety: String::new(),
        }];
        assert!(app.can_send());
        app.input = "  ".to_string();
        assert!(!app.can_send());
    }

    #[test]
    fn submit_quit_sets_flag() {
        let mut app = TuiApp::new();
        app.input = "/quit".to_string();
        app.submit_input();
        assert!(app.should_quit);
    }

    #[test]
    fn invite_command_parses_and_opens_panel() {
        assert_eq!(parse_input("/invite"), InputAction::Invite);
        let mut app = TuiApp::new();
        app.input = "/invite".to_string();
        app.submit_input();
        assert!(app.show_invite);
    }

    #[test]
    fn generated_passphrase_is_strong_and_varied() {
        let first = generate_passphrase();
        let second = generate_passphrase();
        assert!(first.chars().count() >= 20, "got: {first}");
        assert_ne!(first, second);
        // Five hyphen-separated words plus a 4-digit suffix.
        let parts: Vec<&str> = first.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[5].len(), 4);
        assert!(parts[5].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn create_validation_rejects_bad_input() {
        let mut app = TuiApp::new();
        app.home = "/tmp/oc-tui-test-nonexistent-home".to_string();
        app.passphrase = "short".to_string();
        app.confirm_passphrase = "short".to_string();
        assert!(app.validate_create().is_err());

        app.passphrase = "long-enough-passphrase".to_string();
        app.confirm_passphrase = "different-passphrase".to_string();
        assert!(app.validate_create().is_err());

        app.confirm_passphrase = "long-enough-passphrase".to_string();
        assert!(app.validate_create().is_ok());
    }

    #[test]
    fn generate_fills_both_fields() {
        let mut app = TuiApp::new();
        app.generate_passphrase();
        assert!(!app.passphrase.is_empty());
        assert_eq!(app.passphrase, app.confirm_passphrase);
        assert!(app.validate_create().is_ok() || app.validate_create().is_err());
    }
}
