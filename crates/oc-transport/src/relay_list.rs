//! Built-in relay list.
//!
//! The bundled list is intentionally data-only so that it can be signed and
//! updated independently of the client binary. Users can always add their
//! own relays on top.

use oc_core::identity::{Identity, SIGNATURE_LEN, verify_signature};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result};

const DEFAULT_LIST: &str = include_str!("../../../relays/default.json");
const MANIFEST_DOMAIN: &[u8] = b"openchat/relay-manifest/v1";

/// Parsed `relays/*.json` document.
#[derive(Debug, Clone, Deserialize)]
pub struct RelayList {
    /// Format version.
    pub version: u8,
    /// Relay entries.
    #[serde(default)]
    pub relays: Vec<RelayEntry>,
}

/// One relay entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEntry {
    /// Base URL (`https://…` or `wss://…`).
    pub url: String,
    /// Optional human-readable note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Signed, expiring relay manifest.
///
/// The signature covers a canonical JSON document without the signature
/// field, prefixed with `openchat/relay-manifest/v1`. Clients can fetch it
/// from several independent sources and accept it only if the project key
/// verifies and the manifest has not expired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayManifest {
    /// Format version.
    pub version: u8,
    /// UNIX seconds when the manifest was issued.
    pub issued_at: u64,
    /// UNIX seconds after which the manifest must be ignored.
    pub expires_at: u64,
    /// Relay entries.
    #[serde(default)]
    pub relays: Vec<RelayEntry>,
    /// Hex-encoded Ed25519 signature, absent on unsigned drafts.
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Serialize)]
struct ManifestBody<'a> {
    version: u8,
    issued_at: u64,
    expires_at: u64,
    relays: &'a [RelayEntry],
}

impl RelayManifest {
    /// Build an unsigned manifest.
    pub fn new(version: u8, issued_at: u64, expires_at: u64, relays: Vec<RelayEntry>) -> Self {
        Self {
            version,
            issued_at,
            expires_at,
            relays,
            signature: None,
        }
    }

    /// Canonical bytes covered by the signature.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = MANIFEST_DOMAIN.to_vec();
        message.extend_from_slice(&serde_json::to_vec(&ManifestBody {
            version: self.version,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            relays: &self.relays,
        })?);
        Ok(message)
    }

    /// Sign the manifest with a project identity.
    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        self.signature = Some(hex::encode(identity.sign(&self.signing_message()?)));
        Ok(())
    }

    /// Verify the signature, expiry and relay URLs.
    pub fn verify(&self, public_key: &[u8; 32], now: u64) -> Result<Vec<String>> {
        let signature = self
            .signature
            .as_deref()
            .ok_or_else(|| Error::Relay("relay manifest is unsigned".into()))?;
        let bytes = hex::decode(signature)
            .map_err(|_| Error::Relay("relay manifest signature is not hex".into()))?;
        let signature: [u8; SIGNATURE_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Relay("relay manifest signature has wrong length".into()))?;
        let message = self.signing_message()?;
        verify_signature(public_key, &message, &signature)
            .map_err(|_| Error::Relay("relay manifest signature is invalid".into()))?;

        if self.expires_at != 0 && self.expires_at <= now {
            return Err(Error::Relay("relay manifest has expired".into()));
        }
        urls_from_entries(&self.relays)
    }

    /// Validate and return the relay URLs.
    pub fn urls(&self) -> Result<Vec<String>> {
        urls_from_entries(&self.relays)
    }
}

/// Parse a signed manifest without verifying it.
pub fn parse_manifest(json: &str) -> Result<RelayManifest> {
    Ok(serde_json::from_str(json)?)
}

/// Parse a relay list and validate every URL.
pub fn parse_relay_list(json: &str) -> Result<Vec<String>> {
    let list: RelayList = serde_json::from_str(json)?;
    urls_from_entries(&list.relays)
}

fn urls_from_entries(entries: &[RelayEntry]) -> Result<Vec<String>> {
    let mut urls = Vec::with_capacity(entries.len());
    for entry in entries {
        Url::parse(&entry.url).map_err(|error| Error::Url(format!("{}: {error}", entry.url)))?;
        urls.push(entry.url.clone());
    }
    Ok(urls)
}

/// Relay URLs bundled with the client.
pub fn default_relays() -> Result<Vec<String>> {
    parse_relay_list(DEFAULT_LIST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_parses() {
        let relays = default_relays().unwrap();
        for url in relays {
            assert!(Url::parse(&url).is_ok());
        }
    }

    #[test]
    fn signed_manifest_verifies_and_rejects_tampering() {
        let signing_key = Identity::generate();
        let public_key = signing_key.public().ed_bytes();
        let mut manifest = RelayManifest::new(
            1,
            100,
            200,
            vec![RelayEntry {
                url: "https://relay.example".into(),
                note: None,
            }],
        );
        manifest.sign(&signing_key).unwrap();

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed = parse_manifest(&json).unwrap();
        assert_eq!(
            parsed.verify(&public_key, 150).unwrap(),
            vec!["https://relay.example".to_string()]
        );
        assert!(parsed.verify(&public_key, 200).is_err());
        assert!(parsed
            .verify(&Identity::generate().public().ed_bytes(), 150)
            .is_err());

        let mut tampered = parsed.clone();
        tampered.relays[0].url = "https://evil.example".into();
        assert!(tampered.verify(&public_key, 150).is_err());

        let unsigned = RelayManifest::new(1, 100, 200, Vec::new());
        assert!(unsigned.verify(&public_key, 150).is_err());
    }

    #[test]
    fn rejects_invalid_urls() {
        let json = r#"{"version":1,"relays":[{"url":"nope"}]}"#;
        assert!(parse_relay_list(json).is_err());
    }

    #[test]
    fn accepts_empty_list() {
        let json = r#"{"version":1,"relays":[]}"#;
        assert!(parse_relay_list(json).unwrap().is_empty());
    }
}
