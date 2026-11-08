//! WebSocket connections over any TCP stream (direct or via Tor).
//!
//! `tokio-tungstenite`'s `connect_async` always dials TCP itself, which
//! makes SOCKS5/Tor routing impossible. This module dials the TCP
//! stream first (directly or through the Tor proxy), wraps it in TLS
//! when needed, performs the HTTP upgrade manually, and only then
//! hands the buffered stream to tungstenite for framing.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use sha1::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use url::Url;

use crate::socks5::{connect_tcp_mode, TorConfig};
use crate::{Error, Result};

const OP_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum size of the HTTP upgrade response headers.
const MAX_HEADER_BYTES: usize = 8192;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A byte stream: plain TCP or TLS (each possibly via the Tor proxy).
pub enum ConnStream {
    /// Plain TCP.
    Tcp(tokio::net::TcpStream),
    /// TLS over TCP.
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for ConnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// WebSocket stream over a buffered connection stream.
pub type BoxWsStream = WebSocketStream<BufReader<ConnStream>>;

fn tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Connect a WebSocket to `url` (`ws://`/`wss://`), honouring the Tor
/// configuration. `subprotocol` is sent as `Sec-WebSocket-Protocol`
/// (MQTT-over-WS requires `mqtt`).
pub async fn ws_connect(
    url: &Url,
    tor: &TorConfig,
    subprotocol: Option<&str>,
) -> Result<BoxWsStream> {
    let tls = match url.scheme() {
        "wss" => true,
        "ws" => false,
        other => return Err(Error::Url(format!("unsupported scheme {other}"))),
    };
    let host = url
        .host_str()
        .ok_or_else(|| Error::Url("endpoint has no host".into()))?
        .to_string();
    let port = url.port().unwrap_or(if tls { 443 } else { 80 });

    let tcp = connect_tcp_mode(tor, &host, port).await?;

    let stream: ConnStream = if tls {
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| Error::Url("invalid host".into()))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config()));
        let tls_stream = tokio::time::timeout(OP_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Relay(format!("tls connect: {error}")))?;
        ConnStream::Tls(Box::new(tls_stream))
    } else {
        ConnStream::Tcp(tcp)
    };

    // HTTP upgrade, done manually so the stream (and any buffered
    // leftover) can be handed to tungstenite for framing.
    let key = base64::engine::general_purpose::STANDARD
        .encode(oc_core::random_array::<16>());
    let mut path = url.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    if let Some(subprotocol) = subprotocol {
        request.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
    }
    request.push_str("\r\n");

    let mut buffered = BufReader::new(stream);
    buffered
        .write_all(request.as_bytes())
        .await
        .map_err(|error| Error::Relay(format!("ws write: {error}")))?;
    buffered
        .flush()
        .await
        .map_err(|error| Error::Relay(format!("ws write: {error}")))?;

    verify_upgrade(&mut buffered, &key).await?;

    Ok(WebSocketStream::from_raw_socket(
        buffered,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await)
}

/// Read and verify the HTTP 101 upgrade response.
async fn verify_upgrade(stream: &mut BufReader<ConnStream>, key: &str) -> Result<()> {
    let mut raw = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        tokio::time::timeout(OP_TIMEOUT, stream.read_exact(&mut byte))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|error| Error::Relay(format!("ws read: {error}")))?;
        raw.push(byte[0]);
        if raw.len() > MAX_HEADER_BYTES {
            return Err(Error::Relay("ws handshake headers too large".into()));
        }
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.lines();
    let status = lines.next().unwrap_or_default();
    if !status.contains("101") {
        return Err(Error::Relay(format!("ws upgrade rejected: {status}")));
    }
    let expected = {
        let mut hasher = sha1::Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };
    let mut accepted = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Sec-WebSocket-Accept")
                && value.trim() == expected
            {
                accepted = true;
            }
        }
    }
    if !accepted {
        return Err(Error::Relay("ws upgrade: bad accept key".into()));
    }
    Ok(())
}

/// Send one frame (helper for short-lived connections).
pub async fn send_frame(socket: &mut BoxWsStream, frame: Message) -> Result<()> {
    socket.send(frame).await.map_err(Error::Ws)
}

/// Receive the next frame of any type.
pub async fn next_frame(socket: &mut BoxWsStream) -> Result<Option<Message>> {
    match socket.next().await {
        Some(Ok(message)) => Ok(Some(message)),
        Some(Err(error)) => Err(Error::Ws(error)),
        None => Ok(None),
    }
}

/// Receive the next binary frame, skipping other frame types.
pub async fn next_binary(socket: &mut BoxWsStream) -> Result<Option<Vec<u8>>> {
    loop {
        match next_frame(socket).await? {
            Some(Message::Binary(data)) => return Ok(Some(data.to_vec())),
            Some(Message::Close(_)) | None => return Ok(None),
            Some(_) => continue,
        }
    }
}
