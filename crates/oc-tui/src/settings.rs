//! UI settings stored next to the encrypted state (`settings.json`).
//!
//! Only non-secret preferences live here: Tor mode, publish fan-out and
//! whether the invite panel opens on start. The file is plaintext by
//! design — it contains no keys, tokens or message content.

use std::path::{Path, PathBuf};

use oc_transport::TorMode;
use serde::{Deserialize, Serialize};

/// User settings for the TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Tor routing mode.
    #[serde(default)]
    pub tor_mode: TorModeSetting,
    /// How many relays/brokers to publish each event to (1–5).
    #[serde(default = "default_fanout")]
    pub fanout: usize,
    /// Open the invite panel right after unlocking.
    #[serde(default)]
    pub show_invite_on_start: bool,
    /// Use the embedded obfs4/webtunnel bridges with Tor
    /// (needs `obfs4proxy` + `webtunnel-client` in PATH).
    #[serde(default)]
    pub tor_bridges: bool,
    /// Attempt WebRTC direct delivery (opt-in; reveals peer IPs to
    /// each other, needs both sides online).
    #[serde(default)]
    pub webrtc: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tor_mode: TorModeSetting::Off,
            fanout: default_fanout(),
            show_invite_on_start: false,
            tor_bridges: false,
            webrtc: false,
        }
    }
}

fn default_fanout() -> usize {
    3
}

/// Serde-friendly spelling of [`TorMode`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TorModeSetting {
    /// Direct connections, Tor unused.
    #[default]
    Off,
    /// Direct first, Tor on failure.
    Fallback,
    /// Everything through Tor.
    Always,
}

impl TorModeSetting {
    /// Convert to the transport-layer mode.
    pub fn to_mode(self) -> TorMode {
        match self {
            Self::Off => TorMode::Off,
            Self::Fallback => TorMode::Fallback,
            Self::Always => TorMode::Always,
        }
    }

    /// Cycle to the next mode (for the settings menu).
    pub fn next(&self) -> Self {
        match self {
            Self::Off => Self::Fallback,
            Self::Fallback => Self::Always,
            Self::Always => Self::Off,
        }
    }

    /// Cycle to the previous mode (for the settings menu).
    pub fn prev(&self) -> Self {
        match self {
            Self::Off => Self::Always,
            Self::Fallback => Self::Off,
            Self::Always => Self::Fallback,
        }
    }
}

/// Path of the settings file inside a state directory.
pub fn path_in(home: &Path) -> PathBuf {
    home.join("settings.json")
}

/// Load settings, falling back to defaults when absent or invalid.
pub fn load(home: &Path) -> Settings {
    let text = std::fs::read_to_string(path_in(home)).unwrap_or_default();
    serde_json::from_str(&text).unwrap_or_default()
}

/// Persist settings (best effort; failures are reported by the caller).
pub fn save(home: &Path, settings: &Settings) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(settings)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    std::fs::write(path_in(home), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_roundtrip() {
        let settings = Settings::default();
        assert_eq!(settings.fanout, 3);
        assert_eq!(settings.tor_mode, TorModeSetting::Off);
        let text = serde_json::to_string(&settings).unwrap();
        let parsed: Settings = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.fanout, 3);
        assert_eq!(parsed.tor_mode, TorModeSetting::Off);
    }

    #[test]
    fn tor_mode_cycling() {
        assert_eq!(TorModeSetting::Off.next(), TorModeSetting::Fallback);
        assert_eq!(TorModeSetting::Fallback.next(), TorModeSetting::Always);
        assert_eq!(TorModeSetting::Always.next(), TorModeSetting::Off);
        assert_eq!(TorModeSetting::Off.prev(), TorModeSetting::Always);
        assert_eq!(TorModeSetting::Always.to_mode(), TorMode::Always);
    }

    #[test]
    fn load_missing_file_gives_defaults() {
        let settings = load(Path::new("/tmp/oc-tui-definitely-missing-home"));
        assert_eq!(settings.fanout, 3);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "oc-tui-settings-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings {
            tor_mode: TorModeSetting::Always,
            fanout: 5,
            show_invite_on_start: true,
            tor_bridges: true,
            webrtc: true,
        };
        save(&dir, &settings).unwrap();
        let loaded = load(&dir);
        assert_eq!(loaded.tor_mode, TorModeSetting::Always);
        assert_eq!(loaded.fanout, 5);
        assert!(loaded.show_invite_on_start);
        assert!(loaded.tor_bridges);
        std::fs::remove_dir_all(&dir).ok();
    }
}
