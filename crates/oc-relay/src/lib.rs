#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! OpenChat relay.
//!
//! The relay is deliberately dumb: it stores opaque encrypted payloads under
//! one-shot mailbox public keys, enforces size/TTL limits and streams them to
//! subscribers. It has no accounts, no access log and no way to read content.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use oc_wire::{ClientMessage, HealthResponse, RelayEvent, ServerMessage, WIRE_VERSION};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast};

const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const BROADCAST_CAPACITY: usize = 1024;

/// Relay limits.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Maximum event lifetime in seconds.
    pub ttl_seconds: u64,
    /// Maximum number of stored events per mailbox.
    pub max_events_per_mailbox: usize,
    /// Maximum opaque payload size in bytes.
    pub max_payload_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 7 * 24 * 60 * 60,
            max_events_per_mailbox: 100,
            max_payload_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: RelayConfig,
    events: Arc<RwLock<HashMap<[u8; 32], Vec<RelayEvent>>>>,
    tx: broadcast::Sender<RelayEvent>,
}

impl AppState {
    /// Validate, clamp and store one event.
    async fn accept(&self, mut event: RelayEvent) -> Result<(), String> {
        if event.payload.len() > self.config.max_payload_bytes {
            return Err(format!(
                "payload too large: {} > {} bytes",
                event.payload.len(),
                self.config.max_payload_bytes
            ));
        }

        let now = oc_wire::now_unix();
        if event.created_at == 0 || event.created_at > now.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
            event.created_at = now;
        }

        let max_expiry = now.saturating_add(self.config.ttl_seconds);
        if event.expires_at == 0 || event.expires_at > max_expiry {
            event.expires_at = max_expiry;
        }
        if event.expires_at <= now {
            return Err("event is already expired".into());
        }

        {
            let mut store = self.events.write().await;
            let bucket = store.entry(event.mailbox).or_default();
            bucket.retain(|stored| stored.expires_at > now);
            bucket.push(event.clone());

            if bucket.len() > self.config.max_events_per_mailbox {
                let excess = bucket.len() - self.config.max_events_per_mailbox;
                bucket.drain(..excess);
            }
        }

        // No subscribers is not an error.
        let _ = self.tx.send(event);
        Ok(())
    }

    async fn cleanup(&self) {
        let now = oc_wire::now_unix();
        let mut store = self.events.write().await;
        store.retain(|_, events| {
            events.retain(|event| event.expires_at > now);
            !events.is_empty()
        });
    }
}

/// A relay server instance.
pub struct Relay {
    state: AppState,
}

impl Relay {
    /// Create a relay with the given limits.
    pub fn new(config: RelayConfig) -> Self {
        let (tx, _receiver) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            state: AppState {
                config,
                events: Arc::new(RwLock::new(HashMap::new())),
                tx,
            },
        }
    }

    /// Build the HTTP/WebSocket router.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/health", get(health))
            .route("/publish", post(publish_http))
            .route("/ws", get(ws_handler))
            .with_state(self.state.clone())
    }

    /// Serve until the listener fails, with periodic expiry cleanup.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                state.cleanup().await;
            }
        });

        axum::serve(listener, self.router()).await
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: WIRE_VERSION,
    })
}

async fn publish_http(
    State(state): State<AppState>,
    Json(event): Json<RelayEvent>,
) -> Response {
    match state.accept(event).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(message) => (StatusCode::BAD_REQUEST, message).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct SubscribeParams {
    mailbox: Option<String>,
    since: Option<u64>,
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(params): Query<SubscribeParams>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| client_loop(socket, state, params))
}

async fn client_loop(socket: WebSocket, state: AppState, params: SubscribeParams) {
    let (mut sender, mut receiver) = socket.split();

    let mailbox = match params.mailbox.as_deref().map(parse_mailbox).transpose() {
        Ok(mailbox) => mailbox,
        Err(message) => {
            let _ = send_json(&mut sender, &ServerMessage::Error { message }).await;
            let _ = sender.close().await;
            return;
        }
    };

    // Subscribe before the snapshot so no live event can slip between the two.
    let mut live = state.tx.subscribe();
    let since = params.since.unwrap_or(0);

    if let Some(mailbox) = mailbox {
        let stored = state
            .events
            .read()
            .await
            .get(&mailbox)
            .cloned()
            .unwrap_or_default();

        for event in stored {
            if event.created_at > since
                && !send_json(&mut sender, &ServerMessage::Event { event }).await
            {
                return;
            }
        }
    }

    loop {
        tokio::select! {
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMessage>(&text) {
                            Ok(ClientMessage::Ping) => {
                                if !send_json(&mut sender, &ServerMessage::Pong).await {
                                    break;
                                }
                            }
                            Ok(ClientMessage::Publish { event }) => {
                                let reply = match state.accept(event).await {
                                    Ok(()) => ServerMessage::Published,
                                    Err(message) => ServerMessage::Error { message },
                                };
                                if !send_json(&mut sender, &reply).await {
                                    break;
                                }
                            }
                            Err(error) => {
                                let reply = ServerMessage::Error {
                                    message: format!("invalid message: {error}"),
                                };
                                if !send_json(&mut sender, &reply).await {
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            received = live.recv() => {
                match received {
                    Ok(event) => {
                        if let Some(mailbox) = mailbox {
                            if event.mailbox == mailbox
                                && !send_json(&mut sender, &ServerMessage::Event { event }).await
                            {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn send_json(sender: &mut SplitSink<WebSocket, Message>, message: &ServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(message) else {
        return false;
    };
    sender.send(Message::Text(text.into())).await.is_ok()
}

fn parse_mailbox(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| "mailbox must be hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "mailbox must be 32 bytes".to_string())
}
