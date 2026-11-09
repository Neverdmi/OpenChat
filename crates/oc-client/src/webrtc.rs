//! WebRTC data-channel carrier (opt-in, SPEC §9.1 carrier #3).
//!
//! When enabled, two online clients negotiate a direct P2P data channel
//! (signaling over the regular relays, media over ICE/STUN) and exchange
//! sealed mailbox payloads directly instead of via relay storage.
//!
//! Trade-offs, honestly:
//! - both sides must be online at the same time (no store-and-forward);
//! - ICE reveals each side's public IP to the other side (and to the
//!   STUN servers below) — relays never see the traffic, but the peer
//!   learns your IP. That is why this is opt-in, off by default;
//! - Tor mode and WebRTC do not combine (WebRTC needs direct UDP).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtc::peer_connection::transport::RTCIceCandidateInit;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceServer, RTCPeerConnectionIceEvent,
};

use crate::{Error, Result};

/// STUN servers for server-reflexive ICE candidates.
const STUN_SERVERS: &[&str] = &["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"];
/// Maximum queued signaling messages / candidates per session.
const MAX_QUEUED: usize = 128;
/// Maximum SDP text accepted from the peer.
const MAX_SDP_BYTES: usize = 65_536;
/// Data channel label.
const CHANNEL_LABEL: &str = "openchat";

/// One signaling message, exchanged over the signaling mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Signaling {
    /// SDP offer.
    Offer {
        /// Sender peer id.
        from: [u8; 32],
        /// SDP text.
        sdp: String,
    },
    /// SDP answer.
    Answer {
        /// Sender peer id.
        from: [u8; 32],
        /// SDP text.
        sdp: String,
    },
    /// ICE candidate (serialized form).
    Candidate {
        /// Sender peer id.
        from: [u8; 32],
        /// Candidate string as gathered locally.
        candidate: String,
        /// STUN/TURN URL for srflx/relay candidates.
        url: Option<String>,
    },
}

impl Signaling {
    /// Sender peer id of any signaling message.
    pub fn from(&self) -> [u8; 32] {
        match self {
            Self::Offer { from, .. } | Self::Answer { from, .. } | Self::Candidate { from, .. } => {
                *from
            }
        }
    }
}

/// Shared state between the peer-connection event handler and the client.
#[derive(Default)]
pub struct SessionShared {
    /// Data channel, once created (by us or by the remote side).
    pub data_channel: Option<Arc<dyn DataChannel>>,
    /// Signaling messages to publish to the peer.
    pub outbound: VecDeque<Signaling>,
    /// Remote candidates received before the remote description.
    pub pending_candidates: Vec<(String, Option<String>)>,
}

impl SessionShared {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }
}

/// Event handler that funnels ICE candidates and the data channel into
/// the shared session state.
#[derive(Clone)]
struct SessionHandler {
    shared: Arc<Mutex<SessionShared>>,
    own_peer_id: [u8; 32],
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for SessionHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        // `to_json()` produces the init form (candidate with the
        // `candidate:` prefix, as `RTCIceCandidateInit` expects).
        let candidate = event
            .candidate
            .to_json()
            .map(|init| init.candidate)
            .unwrap_or_else(|_| event.candidate.to_string());
        let url = event.candidate.url.clone();
        if let Ok(mut shared) = self.shared.lock() {
            if shared.outbound.len() < MAX_QUEUED {
                shared.outbound.push_back(Signaling::Candidate {
                    from: self.own_peer_id,
                    candidate,
                    url,
                });
            }
        }
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.data_channel = Some(data_channel);
        }
    }
}

/// One WebRTC session with a peer.
pub struct WebRtcSession {
    /// Peer connection.
    pub peer_connection: Arc<dyn PeerConnection>,
    /// Shared handler state.
    pub shared: Arc<Mutex<SessionShared>>,
    /// Our own peer id (stamped into outgoing signaling).
    pub own_peer_id: [u8; 32],
    /// Whether we created the data channel ourselves.
    pub initiator: bool,
    /// Last offer time (for re-offer after a timeout).
    pub last_offer: u64,
    /// Whether the remote description has been applied.
    pub remote_set: bool,
}

impl WebRtcSession {
    /// Build a peer connection with STUN and the session handler.
    pub async fn new(initiator: bool, own_peer_id: [u8; 32]) -> Result<Self> {
        let shared = SessionShared::new();
        let config = RTCConfigurationBuilder::default()
            .with_ice_servers(
                STUN_SERVERS
                    .iter()
                    .map(|url| RTCIceServer {
                        urls: vec![(*url).to_string()],
                        ..Default::default()
                    })
                    .collect(),
            )
            .build();
        let built = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_handler(Arc::new(SessionHandler {
                shared: Arc::clone(&shared),
                own_peer_id,
            }))
            .with_udp_addrs(vec!["0.0.0.0:0"])
            .build()
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))?;
        let peer_connection: Arc<dyn PeerConnection> = Arc::new(built);
        Ok(Self {
            peer_connection,
            shared,
            own_peer_id,
            initiator,
            last_offer: 0,
            remote_set: false,
        })
    }

    /// Create the data channel and the initial offer (initiator side).
    pub async fn offer(&mut self) -> Result<Signaling> {
        let channel = self
            .peer_connection
            .create_data_channel(CHANNEL_LABEL, None)
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))?;
        if let Ok(mut shared) = self.shared.lock() {
            shared.data_channel = Some(channel);
        }
        let offer = self
            .peer_connection
            .create_offer(None)
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))?;
        self.peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))?;
        self.last_offer = oc_core::now_unix();
        Ok(Signaling::Offer {
            from: self.own_peer_id,
            sdp: offer.sdp,
        })
    }

    /// Apply a signaling message from the peer.
    pub async fn apply(&mut self, signaling: &Signaling) -> Result<Option<Signaling>> {
        let sdp_len = match signaling {
            Signaling::Offer { sdp, .. } | Signaling::Answer { sdp, .. } => sdp.len(),
            Signaling::Candidate { candidate, .. } => candidate.len(),
        };
        if sdp_len > MAX_SDP_BYTES {
            return Err(Error::WebRtc("signaling payload too large".into()));
        }
        // Relay replay can redeliver the same offer/answer; applying
        // them twice is a signaling-state error, so ignore duplicates
        // once the remote description is set.
        if self.remote_set
            && matches!(
                signaling,
                Signaling::Offer { .. } | Signaling::Answer { .. }
            )
        {
            return Ok(None);
        }
        match signaling {
            Signaling::Offer { sdp, .. } => {
                let offer = RTCSessionDescription::offer(sdp.clone())
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                self.peer_connection
                    .set_remote_description(offer)
                    .await
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                self.remote_set = true;
                self.flush_candidates().await?;
                let answer = self
                    .peer_connection
                    .create_answer(None)
                    .await
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                self.peer_connection
                    .set_local_description(answer.clone())
                    .await
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                Ok(Some(Signaling::Answer {
                    from: self.own_peer_id,
                    sdp: answer.sdp,
                }))
            }
            Signaling::Answer { sdp, .. } => {
                let answer = RTCSessionDescription::answer(sdp.clone())
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                self.peer_connection
                    .set_remote_description(answer)
                    .await
                    .map_err(|error| Error::WebRtc(error.to_string()))?;
                self.remote_set = true;
                self.flush_candidates().await?;
                Ok(None)
            }
            Signaling::Candidate {
                candidate, url, ..
            } => {
                if self.remote_set {
                    self.add_candidate(candidate, url.clone()).await?;
                } else if let Ok(mut shared) = self.shared.lock() {
                    if shared.pending_candidates.len() < MAX_QUEUED {
                        shared.pending_candidates.push((candidate.clone(), url.clone()));
                    }
                }
                Ok(None)
            }
        }
    }

    async fn add_candidate(&self, candidate: &str, url: Option<String>) -> Result<()> {
        let init = RTCIceCandidateInit {
            candidate: candidate.to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: None,
            url,
        };
        self.peer_connection
            .add_ice_candidate(init)
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))
    }

    /// Apply candidates that arrived before the remote description.
    async fn flush_candidates(&mut self) -> Result<()> {
        let pending: Vec<(String, Option<String>)> = match self.shared.lock() {
            Ok(mut shared) => std::mem::take(&mut shared.pending_candidates),
            Err(_) => Vec::new(),
        };
        for (candidate, url) in pending {
            self.add_candidate(&candidate, url).await?;
        }
        Ok(())
    }

    /// Whether the data channel is open for sending.
    pub async fn is_open(&self) -> bool {
        let channel = match self.shared.lock() {
            Ok(shared) => shared.data_channel.clone(),
            Err(_) => None,
        };
        match channel {
            Some(channel) => channel
                .ready_state()
                .await
                .map(|state| state == webrtc::data_channel::RTCDataChannelState::Open)
                .unwrap_or(false),
            None => false,
        }
    }

    /// Send raw bytes over the data channel.
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        let channel = match self.shared.lock() {
            Ok(shared) => shared.data_channel.clone(),
            Err(_) => return Err(Error::WebRtc("session lock poisoned".into())),
        };
        let channel = channel.ok_or_else(|| Error::WebRtc("no data channel".into()))?;
        channel
            .send(bytes::BytesMut::from(&data[..]))
            .await
            .map_err(|error| Error::WebRtc(error.to_string()))
    }

    /// Poll one incoming data-channel message (short timeout).
    pub async fn poll_message(&self, timeout: std::time::Duration) -> Option<Vec<u8>> {
        let channel = match self.shared.lock() {
            Ok(shared) => shared.data_channel.clone(),
            Err(_) => return None,
        };
        let channel = channel?;
        let event = tokio::time::timeout(timeout, channel.poll()).await.ok()??;
        match event {
            DataChannelEvent::OnMessage(message) => Some(message.data.to_vec()),
            _ => None,
        }
    }

    /// Queue a signaling message for publication.
    pub fn push_outbound(&self, signaling: Signaling) {
        if let Ok(mut shared) = self.shared.lock() {
            if shared.outbound.len() < MAX_QUEUED {
                shared.outbound.push_back(signaling);
            }
        }
    }

    /// Drain signaling messages queued by ICE gathering.
    pub fn take_outbound(&self) -> Vec<Signaling> {
        match self.shared.lock() {
            Ok(mut shared) => shared.outbound.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Whether this session is an initiator waiting for an answer.
    pub fn needs_offer(&self, now: u64) -> bool {
        self.initiator
            && !self.remote_set
            && now.saturating_sub(self.last_offer) > 10
    }

    /// The data-channel state type (for open checks in tests).
    pub fn sdp_type_offer() -> RTCSdpType {
        RTCSdpType::Offer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signaling_json_roundtrip() {
        for message in [
            Signaling::Offer {
                from: [1u8; 32],
                sdp: "v=0\r\n".to_string(),
            },
            Signaling::Answer {
                from: [1u8; 32],
                sdp: "v=0\r\n".to_string(),
            },
            Signaling::Candidate {
                from: [1u8; 32],
                candidate: "candidate:1 1 udp".to_string(),
                url: None,
            },
        ] {
            let json = serde_json::to_string(&message).unwrap();
            let parsed: Signaling = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.from(), [1u8; 32]);
            match (&message, &parsed) {
                (Signaling::Offer { sdp: a, .. }, Signaling::Offer { sdp: b, .. }) => {
                    assert_eq!(a, b)
                }
                (Signaling::Answer { sdp: a, .. }, Signaling::Answer { sdp: b, .. }) => {
                    assert_eq!(a, b)
                }
                (
                    Signaling::Candidate {
                        from: _,
                        candidate: a,
                        url: _,
                    },
                    Signaling::Candidate {
                        from: _,
                        candidate: b,
                        url: _,
                    },
                ) => assert_eq!(a, b),
                _ => panic!("variant changed"),
            }
        }
    }

    #[test]
    fn sdp_type_helper() {
        assert_eq!(WebRtcSession::sdp_type_offer(), RTCSdpType::Offer);
    }
}
