//! `openchat://` invite links.
//!
//! ```text
//! openchat://v1/<peer_id_base32>[/<relay_hints_base64url>]            (short)
//! openchat://v1/<peer_id_base32>/<bundle_base64url>[/<relay_hints_base64url>]  (full, legacy)
//! ```
//!
//! The short form carries only the peer id (~70 characters); the invitee
//! fetches the self-signed bundle from the peer's bundle mailbox on the
//! relays (SPEC §4.2). The full form embeds the bundle directly and is
//! still accepted for compatibility. Relay hints are optional
//! newline-separated URLs encoded with base64url.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use oc_core::x3dh::PrekeyBundle;
use url::Url;

use crate::{Error, Result};

/// Prefix of every v1 invite link.
pub const INVITE_PREFIX: &str = "openchat://v1/";
/// Maximum number of relay hints embedded in one invite.
pub const MAX_RELAY_HINTS: usize = 16;

/// Parsed invite.
#[derive(Clone, Debug)]
pub struct Invite {
    /// Self-certifying peer identifier.
    pub peer_id: [u8; 32],
    /// Signed prekey bundle, when embedded (full form). `None` for the
    /// short form: the bundle is fetched from the bundle mailbox.
    pub bundle: Option<PrekeyBundle>,
    /// Recommended relays (may be empty).
    pub relays: Vec<String>,
}

impl Invite {
    /// Build a full invite, validating the bundle and relay hints.
    pub fn new(bundle: PrekeyBundle, relays: Vec<String>) -> Result<Self> {
        bundle.verify()?;
        validate_relays(&relays)?;
        Ok(Self {
            peer_id: bundle.identity.peer_id(),
            bundle: Some(bundle),
            relays,
        })
    }

    /// Build a short invite: peer id only, bundle fetched from relays.
    pub fn short(peer_id: [u8; 32], relays: Vec<String>) -> Result<Self> {
        validate_relays(&relays)?;
        Ok(Self {
            peer_id,
            bundle: None,
            relays,
        })
    }

    /// Encode to an `openchat://v1/...` string.
    pub fn encode(&self) -> String {
        let peer = BASE32_NOPAD.encode(&self.peer_id);
        let mut link = match &self.bundle {
            Some(bundle) => {
                let encoded = URL_SAFE_NO_PAD.encode(bundle.to_bytes());
                format!("{INVITE_PREFIX}{peer}/{encoded}")
            }
            None => format!("{INVITE_PREFIX}{peer}"),
        };
        if !self.relays.is_empty() {
            let hints = URL_SAFE_NO_PAD.encode(self.relays.join("\n").as_bytes());
            link.push('/');
            link.push_str(&hints);
        }
        link
    }

    /// Parse and verify an invite link.
    pub fn decode(link: &str) -> Result<Self> {
        let link = link.trim();
        let rest = link.strip_prefix(INVITE_PREFIX).ok_or(Error::Invite)?;
        let mut parts = rest.split('/').filter(|part| !part.is_empty());

        let peer_part = parts.next().ok_or(Error::Invite)?;
        let rest: Vec<&str> = parts.collect();
        if rest.len() > 2 {
            return Err(Error::Invite);
        }

        let peer_bytes = BASE32_NOPAD
            .decode(peer_part.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::Invite)?;
        let peer_id: [u8; 32] = peer_bytes.try_into().map_err(|_| Error::Invite)?;

        // With two extra segments the middle one must be a bundle
        // (full form with hints). With one extra segment, try the bundle
        // first and fall back to relay hints (short form with hints):
        // a hints payload decodes to URLs and never to a valid signed
        // bundle, and a bundle never validates as relay URLs.
        let (bundle, relays_part) = match rest.as_slice() {
            [] => (None, None),
            [only] => match parse_bundle(only, &peer_id) {
                Some(bundle) => (Some(bundle), None),
                None => (None, Some(*only)),
            },
            [bundle_part, hints_part] => {
                let bundle = parse_bundle(bundle_part, &peer_id).ok_or(Error::Invite)?;
                (Some(bundle), Some(*hints_part))
            }
            _ => return Err(Error::Invite),
        };

        let relays = match relays_part {
            Some("") | None => Vec::new(),
            Some(encoded) => {
                let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Error::Invite)?;
                let text = String::from_utf8(raw).map_err(|_| Error::Invite)?;
                let relays: Vec<String> = text
                    .split('\n')
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect();
                validate_relays(&relays)?;
                relays
            }
        };

        Ok(Self {
            peer_id,
            bundle,
            relays,
        })
    }
}

/// Base32 form of a peer id, as used in invite links and the CLI.
pub fn peer_id_base32(peer_id: &[u8; 32]) -> String {
    BASE32_NOPAD.encode(peer_id)
}

/// Short display form of a peer id.
pub fn short_peer_id(peer_id: &[u8; 32]) -> String {
    let encoded = peer_id_base32(peer_id);
    encoded[..10.min(encoded.len())].to_string()
}

/// Parse a bundle segment; `None` when it is not a valid signed bundle
/// for `peer_id` (e.g. it is actually relay hints).
fn parse_bundle(encoded: &str, peer_id: &[u8; 32]) -> Option<PrekeyBundle> {
    let bundle_bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let bundle = PrekeyBundle::from_bytes(&bundle_bytes).ok()?;
    bundle.verify().ok()?;
    if bundle.identity.peer_id() != *peer_id {
        return None;
    }
    Some(bundle)
}

fn validate_relays(relays: &[String]) -> Result<()> {
    if relays.len() > MAX_RELAY_HINTS {
        return Err(Error::Invite);
    }
    for relay in relays {
        let url = Url::parse(relay).map_err(|_| Error::Invite)?;
        match url.scheme() {
            "http" | "https" | "ws" | "wss" | "mqtt" | "mqtts" | "mqtttls" => {}
            _ => return Err(Error::Invite),
        }
        if url.host_str().is_none() {
            return Err(Error::Invite);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oc_core::identity::Identity;
    use oc_core::x3dh::PrekeyPair;

    fn invite() -> (Invite, Invite) {
        let bob = Identity::generate();
        let (_, bundle) = PrekeyPair::generate(&bob);
        let invite = Invite::new(
            bundle,
            vec!["https://relay.example".into(), "ws://127.0.0.1:8080".into()],
        )
        .unwrap();
        (invite.clone(), invite)
    }

    #[test]
    fn roundtrip_with_and_without_relays() {
        let (invite, _) = invite();
        let decoded = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(decoded.peer_id, invite.peer_id);
        assert_eq!(decoded.bundle, invite.bundle);
        assert_eq!(decoded.relays, invite.relays);

        let bare = Invite::new(invite.bundle.clone().unwrap(), Vec::new()).unwrap();
        let decoded = Invite::decode(&bare.encode()).unwrap();
        assert!(decoded.relays.is_empty());
    }

    #[test]
    fn short_invite_roundtrip_is_compact() {
        let (full, _) = invite();
        let short = Invite::short(full.peer_id, vec!["https://relay.example".into()]).unwrap();
        let encoded = short.encode();
        // Short form: peer id only, ~70 characters, no bundle segment.
        assert!(encoded.len() < 200, "encoded len {}", encoded.len());
        assert!(short.bundle.is_none());

        let decoded = Invite::decode(&encoded).unwrap();
        assert_eq!(decoded.peer_id, full.peer_id);
        assert!(decoded.bundle.is_none());
        assert_eq!(decoded.relays, vec!["https://relay.example"]);

        // Without hints it is just the peer id.
        let bare = Invite::short(full.peer_id, Vec::new()).unwrap();
        let decoded = Invite::decode(&bare.encode()).unwrap();
        assert!(decoded.bundle.is_none());
        assert!(decoded.relays.is_empty());
    }

    #[test]
    fn rejects_wrong_prefix_and_truncation() {
        let (invite, _) = invite();
        let link = invite.encode();
        assert!(Invite::decode(&link.replacen("openchat://", "other://", 1)).is_err());
        assert!(Invite::decode(&link[..link.len() - 5]).is_err());
        assert!(Invite::decode("openchat://v1/only-one-part").is_err());
    }

    #[test]
    fn rejects_peer_id_mismatch() {
        let (invite, _) = invite();
        let link = invite.encode();
        let mut parts: Vec<&str> = link.split('/').collect();
        // Replace the peer id segment with another valid 32-byte id.
        let other = BASE32_NOPAD.encode(&[9u8; 32]);
        parts[3] = &other;
        let tampered = parts.join("/");
        assert!(Invite::decode(&tampered).is_err());
    }

    #[test]
    fn rejects_unsafe_relay_hints() {
        let bob = Identity::generate();
        let (_, bundle) = PrekeyPair::generate(&bob);
        assert!(Invite::new(bundle.clone(), vec!["ftp://relay.example".into()]).is_err());
        assert!(Invite::short([1u8; 32], vec!["ftp://relay.example".into()]).is_err());
        assert!(Invite::new(bundle, vec!["not a url".into()]).is_err());
    }

    #[test]
    fn mqtt_relay_hints_roundtrip() {
        let bob = Identity::generate();
        let (_, bundle) = PrekeyPair::generate(&bob);
        let invite = Invite::new(
            bundle,
            vec![
                "mqtts://broker.hivemq.com:8884/mqtt".into(),
                "mqtttls://broker.emqx.io:8883".into(),
            ],
        )
        .unwrap();
        let decoded = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(decoded.relays, invite.relays);
    }
}
