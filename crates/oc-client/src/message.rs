//! Application frames and the inner envelope carried by ratchet messages.

use oc_core::frame;
use oc_core::ratchet::{HEADER_LEN, Header};
use oc_core::{PROTOCOL_VERSION, random_array};

use crate::{Error, Result};

/// Envelope kind: X3DH initiation.
pub const KIND_HANDSHAKE: u8 = 1;
/// Envelope kind: ratchet-encrypted text.
pub const KIND_TEXT: u8 = 2;
/// Frame body type: text.
pub const TYPE_TEXT: u8 = 1;
/// Frame body type: delivery acknowledgement.
pub const TYPE_ACK: u8 = 2;

const BODY_HEADER_LEN: usize = 4 + 16 + 8 + 2;
const ENVELOPE_HEADER_LEN: usize = 2;
/// Serialized length of an acknowledgement body.
pub const ACK_BODY_LEN: usize = BODY_HEADER_LEN + 16;

/// Maximum UTF-8 text length in one frame.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Decrypted application body (`SPEC.md` §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextBody {
    /// Random per-message identifier.
    pub msg_id: [u8; 16],
    /// Sender wall-clock time in milliseconds.
    pub timestamp_ms: u64,
    /// UTF-8 text.
    pub text: String,
}

impl TextBody {
    /// Build a text body with a fresh `msg_id` and the current time.
    pub fn new(text: &str) -> Result<Self> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::TextTooLong(MAX_TEXT_BYTES));
        }
        Ok(Self {
            msg_id: random_array::<16>(),
            timestamp_ms: now_millis(),
            text: text.to_owned(),
        })
    }

    /// Serialize the body; the caller pads it with [`oc_core::frame::pad`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = self.text.as_bytes();
        let body_len = u16::try_from(body.len()).map_err(|_| Error::TextTooLong(MAX_TEXT_BYTES))?;

        let mut out = Vec::with_capacity(BODY_HEADER_LEN + body.len());
        encode_header(
            &mut out,
            TYPE_TEXT,
            &self.msg_id,
            self.timestamp_ms,
            body_len,
        );
        out.extend_from_slice(body);
        Ok(out)
    }

    /// Parse a body produced by [`TextBody::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (msg_id, timestamp_ms, body) = decode_header(bytes, TYPE_TEXT)?;
        let text = core::str::from_utf8(body)
            .map_err(|_| Error::InvalidMessage)?
            .to_owned();

        Ok(Self {
            msg_id,
            timestamp_ms,
            text,
        })
    }
}

/// Delivery acknowledgement (`SPEC.md` §8, `type=ACK`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckBody {
    /// Random id of the acknowledgement frame itself.
    pub msg_id: [u8; 16],
    /// Sender wall-clock time in milliseconds.
    pub timestamp_ms: u64,
    /// Message that was successfully decrypted by the peer.
    pub acked_msg_id: [u8; 16],
}

impl AckBody {
    /// Build an acknowledgement with a fresh `msg_id` and the current time.
    pub fn new(acked_msg_id: [u8; 16]) -> Self {
        Self {
            msg_id: random_array::<16>(),
            timestamp_ms: now_millis(),
            acked_msg_id,
        }
    }

    /// Serialize; the caller pads it with [`oc_core::frame::pad`].
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACK_BODY_LEN);
        encode_header(&mut out, TYPE_ACK, &self.msg_id, self.timestamp_ms, 16);
        out.extend_from_slice(&self.acked_msg_id);
        out
    }

    /// Parse an acknowledgement produced by [`AckBody::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (msg_id, timestamp_ms, body) = decode_header(bytes, TYPE_ACK)?;
        if body.len() != 16 {
            return Err(Error::InvalidMessage);
        }
        Ok(Self {
            msg_id,
            timestamp_ms,
            acked_msg_id: body.try_into().expect("length checked"),
        })
    }
}

/// Any application body carried by a ratchet frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// User-visible text.
    Text(TextBody),
    /// Delivery acknowledgement.
    Ack(AckBody),
}

impl Body {
    /// Message id of the body.
    pub fn msg_id(&self) -> [u8; 16] {
        match self {
            Self::Text(text) => text.msg_id,
            Self::Ack(ack) => ack.msg_id,
        }
    }

    /// Serialize the body before padding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Text(text) => text.encode(),
            Self::Ack(ack) => Ok(ack.encode()),
        }
    }

    /// Parse a padded-and-unpadded body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::InvalidMessage);
        }
        match bytes[1] {
            TYPE_TEXT => TextBody::decode(bytes).map(Self::Text),
            TYPE_ACK => AckBody::decode(bytes).map(Self::Ack),
            _ => Err(Error::InvalidMessage),
        }
    }
}

fn encode_header(
    out: &mut Vec<u8>,
    kind: u8,
    msg_id: &[u8; 16],
    timestamp_ms: u64,
    body_len: u16,
) {
    out.push(PROTOCOL_VERSION);
    out.push(kind);
    out.push(0); // flags, reserved for future use
    out.push(0); // reserved
    out.extend_from_slice(msg_id);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&body_len.to_le_bytes());
}

fn decode_header(bytes: &[u8], expected_type: u8) -> Result<([u8; 16], u64, &[u8])> {
    if bytes.len() < BODY_HEADER_LEN {
        return Err(Error::InvalidMessage);
    }
    if bytes[0] != PROTOCOL_VERSION || bytes[1] != expected_type {
        return Err(Error::InvalidMessage);
    }

    let msg_id: [u8; 16] = bytes[4..20].try_into().expect("length checked");
    let timestamp_ms = u64::from_le_bytes(bytes[20..28].try_into().expect("length checked"));
    let body_len = u16::from_le_bytes(bytes[28..30].try_into().expect("length checked")) as usize;

    if BODY_HEADER_LEN + body_len != bytes.len() {
        return Err(Error::InvalidMessage);
    }
    Ok((msg_id, timestamp_ms, &bytes[BODY_HEADER_LEN..]))
}

/// Inner envelope, sealed to a mailbox before it touches the relay.
#[derive(Clone, Debug)]
pub enum Envelope {
    /// Padded X3DH initiation.
    Handshake(Vec<u8>),
    /// Ratchet header plus ciphertext.
    Text {
        /// Ratchet header.
        header: Header,
        /// Ratchet ciphertext (`nonce || AEAD`).
        ciphertext: Vec<u8>,
    },
}

impl Envelope {
    /// Wrap a padded initiation.
    pub fn handshake(padded: Vec<u8>) -> Self {
        Self::Handshake(padded)
    }

    /// Wrap a ratchet-encrypted frame.
    pub fn text(header: Header, ciphertext: Vec<u8>) -> Self {
        Self::Text { header, ciphertext }
    }

    /// Serialize the whole inner envelope.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Handshake(padded) => {
                let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + padded.len());
                out.push(PROTOCOL_VERSION);
                out.push(KIND_HANDSHAKE);
                out.extend_from_slice(padded);
                out
            }
            Self::Text { header, ciphertext } => {
                let mut out =
                    Vec::with_capacity(ENVELOPE_HEADER_LEN + HEADER_LEN + ciphertext.len());
                out.push(PROTOCOL_VERSION);
                out.push(KIND_TEXT);
                out.extend_from_slice(&header.to_bytes());
                out.extend_from_slice(ciphertext);
                out
            }
        }
    }

    /// Parse an inner envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < ENVELOPE_HEADER_LEN || bytes[0] != PROTOCOL_VERSION {
            return Err(Error::InvalidMessage);
        }

        match bytes[1] {
            KIND_HANDSHAKE => Ok(Self::Handshake(bytes[ENVELOPE_HEADER_LEN..].to_vec())),
            KIND_TEXT => {
                if bytes.len() < ENVELOPE_HEADER_LEN + HEADER_LEN {
                    return Err(Error::InvalidMessage);
                }
                let header = Header::from_bytes(
                    &bytes[ENVELOPE_HEADER_LEN..ENVELOPE_HEADER_LEN + HEADER_LEN],
                )?;
                Ok(Self::Text {
                    header,
                    ciphertext: bytes[ENVELOPE_HEADER_LEN + HEADER_LEN..].to_vec(),
                })
            }
            _ => Err(Error::InvalidMessage),
        }
    }
}

/// Pad an application body into a fixed frame bucket.
pub fn pad_body(body: &[u8]) -> Result<Vec<u8>> {
    frame::pad(body).map_err(Error::Core)
}

/// Strip frame padding.
pub fn unpad_body(frame: &[u8]) -> Result<Vec<u8>> {
    frame::unpad(frame)
        .map(|body| body.to_vec())
        .map_err(Error::Core)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_body_roundtrip() {
        let body = TextBody::new("привет, мир").unwrap();
        let encoded = body.encode().unwrap();
        assert_eq!(TextBody::decode(&encoded).unwrap(), body);
    }

    #[test]
    fn rejects_oversized_and_malformed_bodies() {
        let too_long = "x".repeat(MAX_TEXT_BYTES + 1);
        assert!(matches!(
            TextBody::new(&too_long),
            Err(Error::TextTooLong(_))
        ));

        let body = TextBody::new("ok").unwrap().encode().unwrap();
        assert!(TextBody::decode(&body[..body.len() - 1]).is_err());
        assert!(TextBody::decode(&[0u8; 3]).is_err());

        let mut wrong_type = body.clone();
        wrong_type[1] = 99;
        assert!(TextBody::decode(&wrong_type).is_err());
    }

    #[test]
    fn ack_body_roundtrip_and_body_dispatch() {
        let ack = AckBody::new([7u8; 16]);
        let encoded = ack.encode();
        assert_eq!(encoded.len(), ACK_BODY_LEN);
        assert_eq!(AckBody::decode(&encoded).unwrap(), ack);
        assert_eq!(Body::decode(&encoded).unwrap(), Body::Ack(ack));

        let text = TextBody::new("ok").unwrap();
        assert_eq!(
            Body::decode(&text.encode().unwrap()).unwrap(),
            Body::Text(text)
        );

        let mut wrong = encoded;
        wrong[1] = TYPE_TEXT;
        assert!(AckBody::decode(&wrong).is_err());
    }

    #[test]
    fn envelope_roundtrip() {
        let handshake = Envelope::handshake(vec![7u8; 4096]);
        assert!(matches!(
            Envelope::decode(&handshake.encode()).unwrap(),
            Envelope::Handshake(_)
        ));

        let header = Header {
            dh: [3u8; 32],
            pn: 1,
            n: 2,
        };
        let text = Envelope::text(header, vec![9u8; 64]);
        match Envelope::decode(&text.encode()).unwrap() {
            Envelope::Text {
                header: parsed,
                ciphertext,
            } => {
                assert_eq!(parsed, header);
                assert_eq!(ciphertext, vec![9u8; 64]);
            }
            _ => panic!("wrong envelope kind"),
        }
    }

    #[test]
    fn rejects_unknown_envelope_kind() {
        let mut wire = Envelope::handshake(vec![1, 2, 3]).encode();
        wire[1] = 99;
        assert!(Envelope::decode(&wire).is_err());
        assert!(Envelope::decode(&[PROTOCOL_VERSION]).is_err());
    }
}
