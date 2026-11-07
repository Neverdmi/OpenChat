//! Built-in relay list.
//!
//! The bundled list is intentionally data-only so that it can be signed and
//! updated independently of the client binary. Users can always add their
//! own relays on top.

use serde::Deserialize;
use url::Url;

use crate::{Error, Result};

const DEFAULT_LIST: &str = include_str!("../../../relays/default.json");

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
#[derive(Debug, Clone, Deserialize)]
pub struct RelayEntry {
    /// Base URL (`https://…` or `wss://…`).
    pub url: String,
    /// Optional human-readable note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Parse a relay list and validate every URL.
pub fn parse_relay_list(json: &str) -> Result<Vec<String>> {
    let list: RelayList = serde_json::from_str(json)?;
    let mut urls = Vec::with_capacity(list.relays.len());
    for entry in list.relays {
        Url::parse(&entry.url).map_err(|error| Error::Url(format!("{}: {error}", entry.url)))?;
        urls.push(entry.url);
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
