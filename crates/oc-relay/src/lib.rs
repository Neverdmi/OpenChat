#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! OpenChat relay.
//!
//! The relay is deliberately dumb: it stores opaque encrypted payloads under
//! one-shot mailbox public keys, enforces size/TTL limits and streams them to
//! subscribers. It has no accounts, no access log and no way to read content.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
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
const MAX_MAILBOXES_PER_CONNECTION: usize = 4096;
/// Maximum replayed events per subscribe request (audit C4).
const MAX_REPLAY_EVENTS: usize = 500;
/// Maximum WebSocket/HTTP body handled by the relay (audit C5).
const MAX_BODY_BYTES: usize = 128 * 1024;
/// Per-IP publish rate limit: burst and sustained tokens per minute.
const PUBLISH_RATE_PER_MINUTE: u32 = 120;

/// Why an event was rejected.
#[derive(Debug)]
enum Reject {
    /// Malformed or policy-invalid event.
    BadRequest(String),
    /// Per-IP publish rate exceeded.
    RateLimited,
}

/// Relay limits.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Maximum event lifetime in seconds.
    pub ttl_seconds: u64,
    /// Maximum number of stored events per mailbox.
    pub max_events_per_mailbox: usize,
    /// Maximum opaque payload size in bytes.
    pub max_payload_bytes: usize,
    /// Maximum number of mailboxes with stored events (global DoS cap).
    pub max_mailboxes: usize,
    /// Maximum number of stored events across all mailboxes.
    pub max_total_events: usize,
    /// Maximum total stored payload bytes across all mailboxes.
    pub max_total_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 7 * 24 * 60 * 60,
            max_events_per_mailbox: 100,
            max_payload_bytes: 64 * 1024,
            max_mailboxes: 50_000,
            max_total_events: 100_000,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Per-IP publish token bucket.
#[derive(Debug, Clone, Copy)]
struct RateBucket {
    tokens: f64,
    updated: Instant,
}

/// Maximum concurrent WebSocket connections (audit M-T1).
const MAX_CONNECTIONS: usize = 1024;
/// Idle timeout per connection: no frame for 5 minutes closes it.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct AppState {
    config: RelayConfig,
    events: Arc<RwLock<HashMap<[u8; 32], Vec<RelayEvent>>>>,
    /// Running totals over the store (events / payload bytes).
    totals: Arc<RwLock<(usize, usize)>>,
    /// Mailbox first-seen order, for deterministic oldest-first eviction.
    order: Arc<RwLock<VecDeque<[u8; 32]>>>,
    /// Per-IP publish buckets.
    rates: Arc<tokio::sync::Mutex<HashMap<IpAddr, RateBucket>>>,
    /// Concurrent-connection semaphore (audit M-T1).
    connection_permits: Arc<tokio::sync::Semaphore>,
    tx: broadcast::Sender<RelayEvent>,
}

impl AppState {
    /// Check (and consume from) the per-IP publish bucket.
    async fn check_rate(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut rates = self.rates.lock().await;
        let bucket = rates.entry(ip).or_insert(RateBucket {
            tokens: PUBLISH_RATE_PER_MINUTE as f64,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * PUBLISH_RATE_PER_MINUTE as f64 / 60.0)
                .min(PUBLISH_RATE_PER_MINUTE as f64);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Validate, clamp and store one event.
    async fn accept(&self, mut event: RelayEvent) -> Result<(), Reject> {
        if event.payload.len() > self.config.max_payload_bytes {
            return Err(Reject::BadRequest(format!(
                "payload too large: {} > {} bytes",
                event.payload.len(),
                self.config.max_payload_bytes
            )));
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
            return Err(Reject::BadRequest("event is already expired".into()));
        }

        {
            let mut store = self.events.write().await;
            if !store.contains_key(&event.mailbox) {
                if store.len() >= self.config.max_mailboxes {
                    return Err(Reject::RateLimited);
                }
                self.order.write().await.push_back(event.mailbox);
            }
            let bucket = store.entry(event.mailbox).or_default();
            bucket.retain(|stored| stored.expires_at > now);
            bucket.push(event.clone());

            if bucket.len() > self.config.max_events_per_mailbox {
                let excess = bucket.len() - self.config.max_events_per_mailbox;
                bucket.drain(..excess);
            }

            // Global caps: evict the oldest events until back under
            // the event/byte budgets (audit C3).
            let mut totals = self.totals.write().await;
            totals.0 = store.values().map(Vec::len).sum();
            totals.1 = store
                .values()
                .flat_map(|events| events.iter())
                .map(|stored| stored.payload.len())
                .sum();
            while totals.0 > self.config.max_total_events
                || totals.1 > self.config.max_total_bytes
            {
                let Some(oldest_mailbox) = self.order.write().await.pop_front() else {
                    break;
                };
                if let Some(bucket) = store.remove(&oldest_mailbox) {
                    for evicted in &bucket {
                        totals.0 = totals.0.saturating_sub(1);
                        totals.1 = totals.1.saturating_sub(evicted.payload.len());
                    }
                }
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
        let live: HashSet<[u8; 32]> = store.keys().copied().collect();
        self.order.write().await.retain(|mailbox| live.contains(mailbox));
        let mut totals = self.totals.write().await;
        totals.0 = store.values().map(Vec::len).sum();
        totals.1 = store
            .values()
            .flat_map(|events| events.iter())
            .map(|stored| stored.payload.len())
            .sum();
        drop(store);
        drop(totals);
        // Forget IP buckets; they refill on demand.
        self.rates.lock().await.clear();
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
                totals: Arc::new(RwLock::new((0, 0))),
                order: Arc::new(RwLock::new(VecDeque::new())),
                rates: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                connection_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
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
            .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
    }

    /// Serve until the listener fails, with periodic expiry cleanup.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        self.serve_until(listener, std::future::pending()).await
    }

    /// Serve until `shutdown` resolves or the listener fails.
    ///
    /// Used by tests and by deployments that need a graceful stop; the
    /// in-memory queue is lost when the relay stops.
    pub async fn serve_until<F>(self, listener: TcpListener, shutdown: F) -> std::io::Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                state.cleanup().await;
            }
        });

        axum::serve(
            listener,
            self.router()
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
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
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(event): Json<RelayEvent>,
) -> Response {
    if !state.check_rate(peer.ip()).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    match state.accept(event).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(Reject::BadRequest(message)) => (StatusCode::BAD_REQUEST, message).into_response(),
        Err(Reject::RateLimited) => StatusCode::TOO_MANY_REQUESTS.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct SubscribeParams {
    mailbox: Option<String>,
    mailboxes: Option<String>,
    since: Option<u64>,
}

async fn ws_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<SubscribeParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // Connection cap: refuse the upgrade when full.
    let Ok(permit) = state.connection_permits.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_BODY_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            client_loop(socket, state, params, peer.ip()).await;
        })
}

async fn client_loop(
    socket: WebSocket,
    state: AppState,
    params: SubscribeParams,
    peer_ip: IpAddr,
) {
    let (mut sender, mut receiver) = socket.split();

    let initial = match parse_mailboxes(&params) {
        Ok(mailboxes) => mailboxes,
        Err(message) => {
            let _ = send_json(&mut sender, &ServerMessage::Error { message }).await;
            let _ = sender.close().await;
            return;
        }
    };

    // Subscribe before the snapshot so no live event can slip between the two.
    let mut live = state.tx.subscribe();
    let since = params.since.unwrap_or(0);
    let mut subscribed: HashSet<[u8; 32]> = initial.iter().copied().collect();

    if !initial.is_empty() && !replay_events(&state, &initial, since, &mut sender).await {
        return;
    }

    loop {
        tokio::select! {
            // Idle timeout: close connections with no frame for 5 min.
            _ = tokio::time::sleep(CONNECTION_IDLE_TIMEOUT) => break,
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
                                if !state.check_rate(peer_ip).await {
                                    let reply = ServerMessage::Error {
                                        message: "rate limited".into(),
                                    };
                                    if !send_json(&mut sender, &reply).await {
                                        break;
                                    }
                                    continue;
                                }
                                let reply = match state.accept(event).await {
                                    Ok(()) => ServerMessage::Published,
                                    Err(Reject::BadRequest(message)) => {
                                        ServerMessage::Error { message }
                                    }
                                    Err(Reject::RateLimited) => ServerMessage::Error {
                                        message: "store is full (rate limited)".into(),
                                    },
                                };
                                if !send_json(&mut sender, &reply).await {
                                    break;
                                }
                            }
                            Ok(ClientMessage::Subscribe { mailboxes, since }) => {
                                let mut added = Vec::new();
                                let mut overflow = false;
                                for mailbox in mailboxes {
                                    if subscribed.contains(&mailbox) {
                                        continue;
                                    }
                                    if subscribed.len() >= MAX_MAILBOXES_PER_CONNECTION {
                                        overflow = true;
                                        break;
                                    }
                                    subscribed.insert(mailbox);
                                    added.push(mailbox);
                                }

                                if overflow {
                                    let reply = ServerMessage::Error {
                                        message: format!(
                                            "too many mailboxes (max {MAX_MAILBOXES_PER_CONNECTION})"
                                        ),
                                    };
                                    if !send_json(&mut sender, &reply).await {
                                        break;
                                    }
                                } else {
                                    if !added.is_empty()
                                        && !replay_events(&state, &added, since, &mut sender).await
                                    {
                                        break;
                                    }
                                    if !send_json(&mut sender, &ServerMessage::Subscribed).await {
                                        break;
                                    }
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
                        if subscribed.contains(&event.mailbox)
                            && !send_json(&mut sender, &ServerMessage::Event { event }).await
                        {
                            break;
                        }
                    }
                    // Behind the broadcast window: close so the client
                    // reconnects and replays from its cursor instead of
                    // silently losing events (audit M-T6).
                    Err(broadcast::error::RecvError::Lagged(_)) => break,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

/// Replay stored events for the given mailboxes, oldest first.
async fn replay_events(
    state: &AppState,
    mailboxes: &[[u8; 32]],
    since: u64,
    sender: &mut SplitSink<WebSocket, Message>,
) -> bool {
    let now = oc_wire::now_unix();
    let mut events = {
        let store = state.events.read().await;
        let mut out = Vec::new();
        'outer: for mailbox in mailboxes {
            if let Some(bucket) = store.get(mailbox) {
                for event in bucket
                    .iter()
                    .filter(|event| event.created_at > since && event.expires_at > now)
                {
                    out.push(event.clone());
                    if out.len() >= MAX_REPLAY_EVENTS {
                        break 'outer;
                    }
                }
            }
        }
        out
    };

    events.sort_by_key(|event| (event.created_at, event.mailbox));
    for event in events {
        if !send_json(sender, &ServerMessage::Event { event }).await {
            return false;
        }
    }
    true
}

fn parse_mailboxes(params: &SubscribeParams) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    if let Some(mailbox) = params.mailbox.as_deref() {
        out.push(parse_mailbox(mailbox)?);
    }
    if let Some(list) = params.mailboxes.as_deref() {
        // Reject oversized lists before splitting/decoding anything.
        if list.matches(',').count() > MAX_MAILBOXES_PER_CONNECTION {
            return Err(format!(
                "too many mailboxes (max {MAX_MAILBOXES_PER_CONNECTION})"
            ));
        }
        for part in list.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            out.push(parse_mailbox(part)?);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_MAILBOXES_PER_CONNECTION {
        return Err(format!(
            "too many mailboxes (max {MAX_MAILBOXES_PER_CONNECTION})"
        ));
    }
    Ok(out)
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
