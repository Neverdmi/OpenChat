//! Transport error type.

use thiserror::Error;

/// Result alias for the transport layer.
pub type Result<T> = core::result::Result<T, Error>;

/// Transport layer error.
#[derive(Debug, Error)]
pub enum Error {
    /// WebSocket failure.
    #[error("websocket error: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),

    /// JSON encoding or decoding failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid relay URL.
    #[error("invalid relay url: {0}")]
    Url(String),

    /// Relay rejected the request.
    #[error("relay error: {0}")]
    Relay(String),

    /// Connection closed before a reply arrived.
    #[error("connection closed")]
    Closed,

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// No relay in the pool accepted the event.
    #[error("no relay accepted the event")]
    NoRelay,
}
