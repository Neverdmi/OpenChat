//! Client error type.

use thiserror::Error;

/// Result alias for the client crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Client-level error.
#[derive(Debug, Error)]
pub enum Error {
    /// Cryptographic core failure.
    #[error("core error: {0}")]
    Core(#[from] oc_core::Error),

    /// Transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] oc_transport::Error),

    /// JSON encoding or decoding failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Filesystem failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Invite link is malformed.
    #[error("invalid invite link")]
    Invite,

    /// State is missing, corrupted or from an unsupported version.
    #[error("invalid state: {0}")]
    State(String),

    /// Wrong passphrase or corrupted encrypted state.
    #[error("wrong passphrase or corrupted state")]
    BadPassphrase,

    /// Contact is not known.
    #[error("unknown contact")]
    UnknownContact,

    /// Peer argument matches zero or several contacts.
    #[error("ambiguous or unknown peer: {0}")]
    Peer(String),

    /// A pinned identity key changed (possible MITM).
    #[error("TOFU mismatch: identity key changed, refusing to continue")]
    Tofu,

    /// Message or envelope is malformed.
    #[error("invalid message")]
    InvalidMessage,

    /// Text is longer than the protocol allows.
    #[error("text is too long (max {0} bytes)")]
    TextTooLong(usize),

    /// The ratchet has no sending chain yet.
    #[error("session is not ready to send: wait for a message from the peer")]
    SessionNotReady,

    /// No relay is configured.
    #[error("no relays configured")]
    NoRelays,

    /// A required random value could not be generated.
    #[error("randomness source failed")]
    Rng,

    /// WebRTC session failure.
    #[error("webrtc error: {0}")]
    WebRtc(String),
}
