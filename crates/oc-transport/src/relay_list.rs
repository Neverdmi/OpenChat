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

        // No immortal manifests: `expires_at` is required, in the
        // future, and after `issued_at` (with clock-skew tolerance).
        if self.expires_at == 0 || self.expires_at <= now {
            return Err(Error::Relay("relay manifest has expired".into()));
        }
        if self.issued_at > now.saturating_add(SKEW_SECONDS) {
            return Err(Error::Relay("relay manifest issued in the future".into()));
        }
        if self.issued_at > self.expires_at {
            return Err(Error::Relay("relay manifest issued after expiry".into()));
        }
        if self.version != 1 {
            return Err(Error::Relay("unsupported relay manifest version".into()));
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

/// Maximum future skew accepted for manifest timestamps.
const SKEW_SECONDS: u64 = 300;

/// Validate one relay URL against SSRF/downgrade rules (audit H6):
/// no userinfo, no plaintext schemes except loopback, no private or
/// link-local hosting.
fn validate_relay_url(raw: &str) -> Result<()> {
    let url = Url::parse(raw).map_err(|error| Error::Url(error.to_string()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Url("relay URL must not contain credentials".into()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::Url("relay URL has no host".into()))?;
    let scheme = url.scheme();
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    match scheme {
        "https" | "wss" | "mqtts" | "mqtttls" => {
            if is_private_host(host) {
                return Err(Error::Url("relay URL points at a private address".into()));
            }
        }
        "http" | "ws" | "mqtt" => {
            // Plaintext is only acceptable for explicit local setups.
            if !loopback {
                return Err(Error::Url("plaintext relay URLs are only allowed for localhost".into()));
            }
        }
        other => return Err(Error::Url(format!("unsupported relay scheme {other}"))),
    }
    Ok(())
}

/// Whether a host literal is private, link-local or metadata space.
fn is_private_host(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    if ip.is_loopback() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..32).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
                || octets[0] == 0
        }
        std::net::IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.is_unique_local(),
    }
}

fn urls_from_entries(entries: &[RelayEntry]) -> Result<Vec<String>> {
    let mut urls = Vec::with_capacity(entries.len());
    for entry in entries {
        validate_relay_url(&entry.url)?;
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
    fn rejects_downgrade_and_private_urls() {
        // Plaintext off-loopback, credentials, private/metadata hosts.
        for url in [
            "http://relay.example",
            "ws://relay.example",
            "mqtt://relay.example",
            "https://user:pass@relay.example",
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://169.254.169.254",
            "wss://172.16.0.1",
            "ftp://relay.example",
        ] {
            let json = format!(r#"{{"version":1,"relays":[{{"url":"{url}"}}]}}"#);
            assert!(parse_relay_list(&json).is_err(), "should reject {url}");
        }
        // Loopback plaintext (local dev relay) stays allowed.
        for url in ["http://127.0.0.1:8080", "ws://localhost:8080"] {
            let json = format!(r#"{{"version":1,"relays":[{{"url":"{url}"}}]}}"#);
            assert!(parse_relay_list(&json).is_ok(), "should allow {url}");
        }
        // Public TLS schemes pass.
        let json = r#"{"version":1,"relays":[{"url":"mqtts://broker.example:8884/mqtt"}]}"#;
        assert!(parse_relay_list(json).is_ok());
    }

    #[test]
    fn manifest_rejects_immortal_and_future_issued() {
        let signing_key = Identity::generate();
        let public_key = signing_key.public().ed_bytes();
        let mut immortal = RelayManifest::new(1, 100, 0, Vec::new());
        immortal.sign(&signing_key).unwrap();
        assert!(immortal.verify(&public_key, 150).is_err());

        let mut future = RelayManifest::new(1, 10_000, 20_000, Vec::new());
        future.sign(&signing_key).unwrap();
        assert!(future.verify(&public_key, 150).is_err());
    }

    #[test]
    fn accepts_empty_list() {
        let json = r#"{"version":1,"relays":[]}"#;
        assert!(parse_relay_list(json).unwrap().is_empty());
    }
}
