//! MQTT carrier (MQTT 3.1.1 over WSS or native TLS).
//!
//! Public MQTT brokers use a different set of domains and ASNs than
//! WebSocket relays, which makes them a useful second carrier against
//! protocol- or domain-based blocking (SPEC §9.1, carrier #4).
//!
//! Mapping onto [`crate::Carrier`]:
//! - one mailbox = topic `openchat/v1/<mailbox hex>`;
//! - one [`oc_wire::RelayEvent`] = one MQTT `PUBLISH` whose payload is the
//!   same JSON encoding the WebSocket relay uses;
//! - QoS 1 in both directions (the client and broker re-deliver until
//!   acknowledged; duplicates are dropped by the `msg_id` dedup above this
//!   layer, exactly like with several relays in the pool);
//! - `since` is ignored: public brokers do not keep an anonymous,
//!   per-mailbox replay log, so MQTT delivery is live-only and the outbox
//!   retries in `oc-client` are what make offline sending work;
//! - no retained messages, no will, clean session: the broker retains
//!   nothing about a mailbox once the connection closes.
//!
//! Two endpoint flavours, selected by scheme:
//! - `mqtts://` (or `mqtt://`): MQTT over WebSocket. The URL is translated
//!   to `wss://` (or `ws://`) for the upgrade; the path is the broker's
//!   WebSocket path and defaults to `/mqtt` when missing (an explicit
//!   `/` is kept for brokers like Mosquitto that only upgrade on `/`).
//! - `mqtttls://`: MQTT over native TLS TCP (typically port 8883), no
//!   WebSocket framing. The path is ignored.
//!
//! Optional `user:pass@` userinfo is sent as MQTT username/password.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use oc_core::random_array;
use oc_wire::RelayEvent;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::socks5::{connect_tcp_mode, TorConfig};
use crate::ws::{ws_connect, BoxWsStream};

use crate::{Carrier, Error, EventStream, Result};

const OP_TIMEOUT: Duration = Duration::from_secs(15);
/// Send a `PINGREQ` after this much inbound silence on a subscription.
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// MQTT keep-alive advertised in `CONNECT`, in seconds.
const KEEPALIVE_SECS: u16 = 60;
/// Largest incoming MQTT payload we are willing to buffer.
const MAX_PAYLOAD: usize = 1024 * 1024;

const OP_CONNECT: u8 = 1;
const OP_CONNACK: u8 = 2;
const OP_PUBLISH: u8 = 3;
const OP_PUBACK: u8 = 4;
const OP_SUBSCRIBE: u8 = 8;
const OP_SUBACK: u8 = 9;
const OP_PINGREQ: u8 = 12;
const OP_PINGRESP: u8 = 13;

/// Topic prefix for every mailbox.
pub const TOPIC_PREFIX: &str = "openchat/v1/";

type WsSocket = BoxWsStream;
type TlsSocket = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// One MQTT connection, either over WebSocket or native TLS TCP.
enum Conn {
    /// MQTT over WebSocket Secure.
    Ws(Box<WsSocket>),
    /// MQTT over native TLS TCP.
    Tls(Box<TlsSocket>),
}

impl Conn {
    /// Send one MQTT packet.
    async fn send_packet(&mut self, packet: Vec<u8>) -> Result<()> {
        match self {
            Conn::Ws(socket) => socket
                .send(Message::Binary(packet.into()))
                .await
                .map_err(Error::Ws),
            Conn::Tls(socket) => {
                use tokio::io::AsyncWriteExt;
                socket
                    .write_all(&packet)
                    .await
                    .map_err(|error| Error::Relay(format!("tls write: {error}")))?;
                socket
                    .flush()
                    .await
                    .map_err(|error| Error::Relay(format!("tls write: {error}")))?;
                Ok(())
            }
        }
    }

    /// Receive one MQTT packet, or `None` on a clean EOF.
    async fn recv_packet(&mut self) -> Result<Option<Vec<u8>>> {
        match self {
            Conn::Ws(socket) => loop {
                match socket.next().await {
                    Some(Ok(Message::Binary(data))) => return Ok(Some(data.to_vec())),
                    Some(Ok(Message::Close(_))) | None => return Ok(None),
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => return Err(Error::Ws(error)),
                }
            },
            Conn::Tls(socket) => read_tls_packet(socket).await,
        }
    }
}

/// Read one framed MQTT packet from a raw TLS byte stream.
async fn read_tls_packet(socket: &mut TlsSocket) -> Result<Option<Vec<u8>>> {
    let mut first = [0u8; 1];
    match socket.read(&mut first).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(error) => return Err(Error::Relay(format!("tls read: {error}"))),
    }
    // Remaining length: 1–4 bytes, 7 bits each, MSB = continuation.
    let mut length: usize = 0;
    let mut multiplier: usize = 1;
    let mut packet = vec![first[0]];
    loop {
        let mut byte = [0u8; 1];
        socket
            .read_exact(&mut byte)
            .await
            .map_err(|error| Error::Relay(format!("tls read: {error}")))?;
        packet.push(byte[0]);
        length += (byte[0] as usize & 0x7F) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
    }
    if length > MAX_PAYLOAD {
        return Err(Error::Relay("mqtt packet too large".into()));
    }
    let mut body = vec![0u8; length];
    socket
        .read_exact(&mut body)
        .await
        .map_err(|error| Error::Relay(format!("tls read: {error}")))?;
    packet.extend_from_slice(&body);
    Ok(Some(packet))
}

/// MQTT client for one broker endpoint.
#[derive(Debug, Clone)]
pub struct MqttClient {
    base: Url,
    tor: TorConfig,
}

impl MqttClient {
    /// Create a client from an already parsed URL.
    ///
    /// Accepted schemes: `mqtts`, `mqtt`, `wss`, `ws`, `https`, `http`
    /// (MQTT over WebSocket) and `mqtttls` (MQTT over native TLS TCP).
    /// The `mqtt(s)://` and `mqtttls://` schemes are how
    /// [`crate::RelayPool::add_url`] recognises an MQTT endpoint.
    pub fn new(base: Url) -> Self {
        // Native TLS needs a process-level rustls provider (`ring`);
        // the WebSocket path installs it too, this keeps MQTT usable
        // on its own.
        crate::client::install_crypto_provider();
        Self {
            base,
            tor: TorConfig::direct(),
        }
    }

    /// Route this client's connections through Tor according to `tor`.
    pub fn with_tor(mut self, tor: TorConfig) -> Self {
        self.tor = tor;
        self
    }

    /// Whether this endpoint uses native TLS instead of WebSocket framing.
    pub fn is_native_tls(&self) -> bool {
        self.base.scheme() == "mqtttls"
    }

    /// Create a client from a string URL.
    pub fn from_url(url: &str) -> Result<Self> {
        let base = Url::parse(url).map_err(|error| Error::Url(error.to_string()))?;
        Ok(Self::new(base))
    }

    /// Base endpoint.
    pub fn url(&self) -> &Url {
        &self.base
    }

    fn ws_url(&self) -> Result<Url> {
        let scheme = match self.base.scheme() {
            "mqtt" | "ws" | "http" => "ws",
            "mqtts" | "wss" | "https" => "wss",
            other => return Err(Error::Url(format!("unsupported scheme {other}"))),
        };
        // `Url::set_scheme` refuses to cross the special/non-special scheme
        // boundary (`mqtts:` -> `wss:`), so rebuild the URL textually.
        let raw = self.base.as_str();
        let Some((_, rest)) = raw.split_once("://") else {
            return Err(Error::Url("invalid mqtt endpoint".into()));
        };
        let mut url = Url::parse(&format!("{scheme}://{rest}"))
            .map_err(|error| Error::Url(error.to_string()))?;
        // An explicit "/" is kept: Mosquitto's WebSocket listener only
        // upgrades on "/" (its `websocket_path`), while HiveMQ/EMQX
        // accept "/mqtt". A missing path defaults to "/mqtt". (After the
        // scheme swap the URL parser normalises an empty path to "/", so
        // the decision uses the original endpoint's path.)
        if self.base.path().is_empty() {
            url.set_path("/mqtt");
        }
        Ok(url)
    }

    async fn connect(&self) -> Result<Conn> {
        let mut conn = if self.is_native_tls() {
            Conn::Tls(Box::new(self.connect_tls().await?))
        } else {
            Conn::Ws(Box::new(self.connect_ws().await?))
        };
        let client_id = hex::encode(random_array::<16>());
        let packet = build_connect(
            &client_id,
            self.base.username(),
            self.base.password(),
        );
        conn.send_packet(packet).await?;
        wait_connack(&mut conn).await?;
        Ok(conn)
    }

    async fn connect_ws(&self) -> Result<WsSocket> {
        let url = self.ws_url()?;
        // MQTT over WebSocket requires the `mqtt` subprotocol; strict
        // brokers (e.g. Mosquitto) reject upgrades without it.
        tokio::time::timeout(OP_TIMEOUT, ws_connect(&url, &self.tor, Some("mqtt")))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn connect_tls(&self) -> Result<TlsSocket> {
        let host = self
            .base
            .host_str()
            .ok_or_else(|| Error::Url("mqtt endpoint has no host".into()))?
            .to_string();
        let port = self.base.port().unwrap_or(8883);
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| Error::Url("invalid mqtt host".into()))?;
        let tcp = tokio::time::timeout(OP_TIMEOUT, connect_tcp_mode(&self.tor, &host, port))
            .await
            .map_err(|_| Error::Timeout)??;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        tokio::time::timeout(OP_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Relay(format!("tls connect: {error}")))
    }
}

#[async_trait]
impl Carrier for MqttClient {
    fn endpoint(&self) -> &Url {
        &self.base
    }

    async fn health(&self) -> Result<()> {
        let mut conn = self.connect().await?;
        conn.send_packet(build_pingreq()).await?;
        loop {
            let packet = next_packet(&mut conn).await?;
            if packet_opcode(&packet) == OP_PINGRESP {
                return Ok(());
            }
        }
    }

    async fn publish(&self, event: &RelayEvent) -> Result<()> {
        let mut conn = self.connect().await?;
        let topic = topic_for(&event.mailbox);
        let payload = serde_json::to_vec(event)?;
        let packet_id = next_packet_id();
        conn.send_packet(build_publish(&topic, &payload, packet_id))
            .await?;
        loop {
            let packet = next_packet(&mut conn).await?;
            if packet_opcode(&packet) == OP_PUBACK && parse_puback(&packet) == Some(packet_id) {
                return Ok(());
            }
        }
    }

    async fn subscribe(&self, mailbox: &[u8; 32], since: u64) -> Result<EventStream> {
        // `since` cannot be honoured by a public broker (live-only, see
        // the module documentation); the parameter exists for the trait.
        let _ = since;
        self.subscribe_many(core::slice::from_ref(mailbox), since).await
    }

    async fn subscribe_many(&self, mailboxes: &[[u8; 32]], since: u64) -> Result<EventStream> {
        let _ = since;
        if mailboxes.is_empty() {
            return Err(Error::Relay("no mailboxes requested".into()));
        }
        let mut conn = self.connect().await?;
        let topics: Vec<String> = mailboxes.iter().map(topic_for).collect();
        let packet_id = next_packet_id();
        conn.send_packet(build_subscribe(packet_id, &topics))
            .await?;
        // Wait for the SUBACK, silently absorbing anything else.
        loop {
            let packet = next_packet(&mut conn).await?;
            if packet_opcode(&packet) == OP_SUBACK {
                break;
            }
        }
        Ok(subscription_stream(conn))
    }
}

/// Topic for one mailbox: `openchat/v1/<hex>`.
pub fn topic_for(mailbox: &[u8; 32]) -> String {
    format!("{TOPIC_PREFIX}{}", hex::encode(mailbox))
}

/// Inverse of [`topic_for`]; `None` for foreign topics.
pub fn mailbox_from_topic(topic: &str) -> Option<[u8; 32]> {
    let hex_part = topic.strip_prefix(TOPIC_PREFIX)?;
    let bytes = hex::decode(hex_part).ok()?;
    bytes.try_into().ok()
}

fn next_packet_id() -> u16 {
    let bytes = random_array::<2>();
    let id = u16::from_le_bytes(bytes);
    if id == 0 { 1 } else { id }
}

fn subscription_stream(conn: Conn) -> EventStream {
    Box::pin(futures_util::stream::unfold(conn, |mut conn| async move {
        loop {
            let received = tokio::select! {
                received = conn.recv_packet() => received,
                _ = tokio::time::sleep(PING_INTERVAL) => {
                    let _ = conn.send_packet(build_pingreq()).await;
                    continue;
                }
            };
            match received {
                Ok(Some(data)) => {
                    if packet_opcode(&data) != OP_PUBLISH {
                        continue;
                    }
                    let Some((topic, payload, qos, packet_id)) = parse_publish(&data) else {
                        continue;
                    };
                    if qos > 0 {
                        if let Some(packet_id) = packet_id {
                            let _ = conn.send_packet(build_puback(packet_id)).await;
                        }
                    }
                    let Some(mailbox) = mailbox_from_topic(&topic) else {
                        continue;
                    };
                    match serde_json::from_slice::<RelayEvent>(&payload) {
                        Ok(event) if event.mailbox == mailbox => {
                            return Some((Ok(event), conn));
                        }
                        Ok(_) => continue,
                        Err(error) => return Some((Err(Error::Json(error)), conn)),
                    }
                }
                Ok(None) => return None,
                Err(error) => return Some((Err(error), conn)),
            }
        }
    }))
}

async fn next_packet(conn: &mut Conn) -> Result<Vec<u8>> {
    let received = tokio::time::timeout(OP_TIMEOUT, conn.recv_packet())
        .await
        .map_err(|_| Error::Timeout)?;
    match received? {
        Some(packet) => Ok(packet),
        None => Err(Error::Closed),
    }
}

async fn wait_connack(conn: &mut Conn) -> Result<()> {
    loop {
        let packet = next_packet(conn).await?;
        if packet_opcode(&packet) != OP_CONNACK {
            continue;
        }
        return match parse_connack(&packet) {
            Some(0) => Ok(()),
            Some(code) => Err(Error::Relay(format!("broker refused connection (code {code})"))),
            None => Err(Error::Relay("malformed CONNACK".into())),
        };
    }
}

// --- MQTT 3.1.1 packet encoding (fixed header + variable body) ---

fn encode_remaining_length(mut length: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            break;
        }
    }
}

fn encode_string(value: &str, out: &mut Vec<u8>) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn packet(opcode: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(opcode << 4 | flags);
    encode_remaining_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn build_connect(client_id: &str, username: &str, password: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    encode_string("MQTT", &mut body);
    body.extend_from_slice(&[4]); // protocol level 3.1.1
    let mut flags = 0x02; // clean session
    if !username.is_empty() {
        flags |= 0x80;
        if password.is_some() {
            flags |= 0x40;
        }
    }
    body.push(flags);
    body.extend_from_slice(&KEEPALIVE_SECS.to_be_bytes());
    encode_string(client_id, &mut body);
    if !username.is_empty() {
        encode_string(username, &mut body);
        if let Some(password) = password {
            encode_string(password, &mut body);
        }
    }
    packet(OP_CONNECT, 0, &body)
}

fn build_publish(topic: &str, payload: &[u8], packet_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    encode_string(topic, &mut body);
    body.extend_from_slice(&packet_id.to_be_bytes());
    body.extend_from_slice(payload);
    packet(OP_PUBLISH, 0x02, &body) // QoS 1
}

fn build_subscribe(packet_id: u16, topics: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    for topic in topics {
        encode_string(topic, &mut body);
        body.push(1); // requested QoS 1
    }
    packet(OP_SUBSCRIBE, 0x02, &body)
}

fn build_puback(packet_id: u16) -> Vec<u8> {
    packet(OP_PUBACK, 0, &packet_id.to_be_bytes())
}

fn build_pingreq() -> Vec<u8> {
    packet(OP_PINGREQ, 0, &[])
}

fn packet_opcode(data: &[u8]) -> u8 {
    data.first().map(|byte| byte >> 4).unwrap_or(0)
}

/// Split a packet into (opcode, body), validating the remaining length.
fn split_packet(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let opcode = data[0] >> 4;
    let mut length: usize = 0;
    let mut multiplier: usize = 1;
    let mut index = 1;
    loop {
        let byte = *data.get(index)?;
        length += (byte as usize & 0x7F) * multiplier;
        index += 1;
        if byte & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return None;
        }
    }
    let body = data.get(index..index.checked_add(length)?)?;
    Some((opcode, body))
}

fn parse_connack(data: &[u8]) -> Option<u8> {
    let (opcode, body) = split_packet(data)?;
    if opcode != OP_CONNACK || body.len() < 2 {
        return None;
    }
    Some(body[1])
}

fn parse_puback(data: &[u8]) -> Option<u16> {
    let (opcode, body) = split_packet(data)?;
    if opcode != OP_PUBACK || body.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([body[0], body[1]]))
}

/// Parse a `PUBLISH` into (topic, payload, qos, packet id).
fn parse_publish(data: &[u8]) -> Option<(String, Vec<u8>, u8, Option<u16>)> {
    if data.is_empty() {
        return None;
    }
    let qos = (data[0] >> 1) & 0x03;
    let (_, body) = split_packet(data)?;
    if body.len() < 2 {
        return None;
    }
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let topic_end = 2usize.checked_add(topic_len)?;
    let topic_bytes = body.get(2..topic_end)?;
    let topic = String::from_utf8(topic_bytes.to_vec()).ok()?;
    let rest = &body[topic_end..];
    let (packet_id, payload) = if qos > 0 {
        if rest.len() < 2 {
            return None;
        }
        (
            Some(u16::from_be_bytes([rest[0], rest[1]])),
            rest[2..].to_vec(),
        )
    } else {
        (None, rest.to_vec())
    };
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    Some((topic, payload, qos, packet_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_roundtrip() {
        let mailbox = [0xABu8; 32];
        let topic = topic_for(&mailbox);
        assert!(topic.starts_with(TOPIC_PREFIX));
        assert_eq!(mailbox_from_topic(&topic), Some(mailbox));
        assert_eq!(mailbox_from_topic("openchat/v1/nothex"), None);
        assert_eq!(mailbox_from_topic("other/v1/ab"), None);
        assert_eq!(mailbox_from_topic("openchat/v1/00"), None);
    }

    #[test]
    fn remaining_length_encoding() {
        for (length, expected) in [
            (0usize, vec![0u8]),
            (127, vec![127]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xFF, 0x7F]),
            (16_384, vec![0x80, 0x80, 0x01]),
        ] {
            let mut encoded = Vec::new();
            encode_remaining_length(length, &mut encoded);
            assert_eq!(encoded, expected, "length {length}");
        }
    }

    #[test]
    fn publish_packet_roundtrip() {
        let event = RelayEvent::new([7u8; 32], vec![1, 2, 3], 60);
        let payload = serde_json::to_vec(&event).unwrap();
        let packet = build_publish(&topic_for(&event.mailbox), &payload, 42);
        let (topic, parsed_payload, qos, packet_id) = parse_publish(&packet).unwrap();
        assert_eq!(qos, 1);
        assert_eq!(packet_id, Some(42));
        let parsed: RelayEvent = serde_json::from_slice(&parsed_payload).unwrap();
        assert_eq!(parsed, event);
        assert_eq!(mailbox_from_topic(&topic), Some(event.mailbox));
    }

    #[test]
    fn connect_and_ack_packets() {
        let connect = build_connect("client-1", "", None);
        assert_eq!(packet_opcode(&connect), OP_CONNECT);
        let (opcode, body) = split_packet(&connect).unwrap();
        assert_eq!(opcode, OP_CONNECT);
        assert!(body.windows(4).any(|window| window == b"MQTT"));

        // CONNACK success: flags 0x20, remaining length 2, session-present 0, rc 0.
        assert_eq!(parse_connack(&[0x20, 0x02, 0x00, 0x00]), Some(0));
        assert_eq!(parse_connack(&[0x20, 0x02, 0x00, 0x05]), Some(5));
        assert_eq!(parse_connack(&[0x20, 0x02, 0x00]), None);

        let puback = build_puback(7);
        assert_eq!(parse_puback(&puback), Some(7));
        assert_eq!(packet_opcode(&build_pingreq()), OP_PINGREQ);

        let subscribe = build_subscribe(9, &[topic_for(&[1u8; 32])]);
        assert_eq!(packet_opcode(&subscribe), OP_SUBSCRIBE);
        let (_, body) = split_packet(&subscribe).unwrap();
        assert_eq!(&body[0..2], &[0, 9]);
    }

    #[test]
    fn ws_url_translation() {
        let client = MqttClient::from_url("mqtts://broker.example").unwrap();
        assert_eq!(client.ws_url().unwrap().as_str(), "wss://broker.example/mqtt");

        let client = MqttClient::from_url("mqtts://broker.example/custom").unwrap();
        assert_eq!(
            client.ws_url().unwrap().as_str(),
            "wss://broker.example/custom"
        );

        let client = MqttClient::from_url("mqtt://broker.example:1883/mqtt").unwrap();
        assert_eq!(
            client.ws_url().unwrap().as_str(),
            "ws://broker.example:1883/mqtt"
        );

        let client = MqttClient::from_url("ftp://broker.example").unwrap();
        assert!(client.ws_url().is_err());
    }

    #[test]
    fn native_tls_scheme_detection() {
        let client = MqttClient::from_url("mqtttls://broker.example:8883").unwrap();
        assert!(client.is_native_tls());
        let client = MqttClient::from_url("mqtts://broker.example:8884/mqtt").unwrap();
        assert!(!client.is_native_tls());
    }

    #[test]
    fn malformed_packets_are_rejected() {
        assert_eq!(split_packet(&[]), None);
        assert_eq!(split_packet(&[0x30]), None);
        assert_eq!(parse_publish(&[0x30, 0x02, 0x00]), None);
        // Remaining length claims more bytes than the packet holds.
        assert_eq!(split_packet(&[0x30, 0x7F, 0x00]), None);
    }
}
