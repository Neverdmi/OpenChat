#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! OpenChat client.
//!
//! Ties the cryptographic core to the relay transport:
//!
//! - encrypted on-disk state (`state.json` sealed with XChaCha20-Poly1305),
//! - `openchat://` invites carrying a signed prekey bundle,
//! - hybrid X3DH handshakes through a sealed handshake mailbox,
//! - Double Ratchet text messages through rotating one-shot mailboxes,
//! - TOFU pinning and message de-duplication.

pub mod client;
pub mod error;
pub mod invite;
pub mod message;
pub mod state;
pub mod store;

pub use client::{
    Client, ContactSummary, ListenOutcome, ReceivedAck, ReceivedMessage, SentMessage,
};
pub use error::{Error, Result};
pub use invite::Invite;
pub use state::{ClientState, ContactRecord, OutboxRecord};
pub use store::StateStore;
