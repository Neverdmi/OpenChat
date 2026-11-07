#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Wire types for the OpenChat relay protocol.
//!
//! The relay is a dumb, untrusted store-and-forward queue. It only ever sees
//! a one-shot mailbox public key, timestamps and opaque ciphertext.

use serde::{Deserialize, Serialize};

/// Relay protocol version.
pub const WIRE_VERSION: u8 = 1;

/// One opaque encrypted message waiting in a mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEvent {
    /// One-shot X25519 mailbox address (hex on the wire).
    #[serde(with = "hex32")]
    pub mailbox: [u8; 32],
    /// UNIX seconds when the event was created.
    pub created_at: u64,
    /// UNIX seconds after which the relay may drop the event.
    pub expires_at: u64,
    /// Sealed sender envelope (base64url on the wire).
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
}

impl RelayEvent {
    /// Build an event with a relative time-to-live.
    pub fn new(mailbox: [u8; 32], payload: Vec<u8>, ttl_seconds: u64) -> Self {
        let now = now_unix();
        Self {
            mailbox,
            created_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            payload,
        }
    }
}

/// Messages sent by a client over the relay WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Store an event for later delivery.
    Publish {
        /// Event to store.
        event: RelayEvent,
    },
    /// Liveness check.
    Ping,
}

/// Messages sent by the relay to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// A stored or live event for the subscribed mailbox.
    Event {
        /// The event.
        event: RelayEvent,
    },
    /// Acknowledgement of a successful publish.
    Published,
    /// Reply to [`ClientMessage::Ping`].
    Pong,
    /// Publish or protocol error.
    Error {
        /// Human-readable reason. Contains no peer information.
        message: String,
    },
}

/// Response body of `GET /health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `ok` on a healthy relay.
    pub status: String,
    /// Relay wire version.
    pub version: u8,
}

/// Current UNIX time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_roundtrip() {
        let event = RelayEvent::new([0xAB; 32], vec![1, 2, 3, 4], 60);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"mailbox\":\"ababab"));
        let parsed: RelayEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn mailbox_must_be_32_bytes() {
        let json = r#"{"mailbox":"00","created_at":0,"expires_at":0,"payload":""}"#;
        assert!(serde_json::from_str::<RelayEvent>(json).is_err());
    }

    #[test]
    fn protocol_messages_have_stable_tags() {
        let publish = ClientMessage::Publish {
            event: RelayEvent::new([1u8; 32], vec![9], 60),
        };
        let json = serde_json::to_string(&publish).unwrap();
        assert!(json.starts_with(r#"{"type":"publish""#));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, publish);

        let pong: ServerMessage = serde_json::from_str(r#"{"type":"pong"}"#).unwrap();
        assert_eq!(pong, ServerMessage::Pong);
    }
}
