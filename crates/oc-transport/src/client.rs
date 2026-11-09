//! WebSocket relay client.

use std::sync::Once;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use oc_wire::{ClientMessage, RelayEvent, ServerMessage};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::socks5::TorConfig;
use crate::ws::{next_frame, send_frame, ws_connect, BoxWsStream};
use crate::{Carrier, Error, EventStream, Result};
use crate::OP_TIMEOUT;

const WS_PATH: &str = "/ws";

static INSTALL_PROVIDER: Once = Once::new();

pub(crate) fn install_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        // rustls needs an explicit provider (`ring`, no cmake/aws-lc).
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// WebSocket client for one relay.
#[derive(Clone)]
pub struct RelayClient {
    base: Url,
    /// URL without userinfo, for display (never log credentials).
    display: Url,
    tor: TorConfig,
}

impl core::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayClient")
            .field("endpoint", &self.display)
            .field("tor_mode", &self.tor.mode)
            .finish_non_exhaustive()
    }
}

impl RelayClient {
    /// Create a client from an already parsed URL.
    ///
    /// Both `http(s)://` and `ws(s)://` are accepted.
    pub fn new(base: Url) -> Self {
        install_crypto_provider();
        let display = crate::mqtt::sanitized(&base);
        Self {
            base,
            display,
            tor: TorConfig::direct(),
        }
    }

    /// Route this client's connections through Tor according to `tor`.
    pub fn with_tor(mut self, tor: TorConfig) -> Self {
        self.tor = tor;
        self
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

    fn ws_url(&self, mailbox: Option<&[u8; 32]>, since: u64) -> Result<Url> {
        let mut url = self.base.clone();
        let scheme = match url.scheme() {
            "http" | "ws" => "ws",
            "https" | "wss" => "wss",
            other => return Err(Error::Url(format!("unsupported scheme {other}"))),
        };
        url.set_scheme(scheme)
            .map_err(|_| Error::Url("cannot set websocket scheme".into()))?;
        url.set_path(WS_PATH);
        url.set_query(None);

        if let Some(mailbox) = mailbox {
            url.query_pairs_mut()
                .append_pair("mailbox", &hex::encode(mailbox))
                .append_pair("since", &since.to_string());
        }
        Ok(url)
    }

    async fn connect(&self, url: &Url) -> Result<BoxWsStream> {
        tokio::time::timeout(OP_TIMEOUT, ws_connect(url, &self.tor, None))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn roundtrip(&self, message: &ClientMessage) -> Result<ServerMessage> {
        let url = self.ws_url(None, 0)?;
        let mut socket = self.connect(&url).await?;

        let text = serde_json::to_string(message)?;
        send_frame(&mut socket, Message::Text(text.into())).await?;

        // Overall deadline (audit M-T4): trickling frames must not
        // pin this call forever.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout);
            }
            let frame = tokio::time::timeout(remaining, next_frame(&mut socket))
                .await
                .map_err(|_| Error::Timeout)??;
            match frame {
                Some(Message::Text(text)) => {
                    return Ok(serde_json::from_str(&text)?);
                }
                Some(Message::Close(_)) | None => return Err(Error::Closed),
                Some(_) => continue,
            }
        }
    }
}

#[async_trait]
impl Carrier for RelayClient {
    fn endpoint(&self) -> &Url {
        &self.display
    }

    async fn health(&self) -> Result<()> {
        match self.roundtrip(&ClientMessage::Ping).await? {
            ServerMessage::Pong => Ok(()),
            ServerMessage::Error { message } => Err(Error::Relay(message)),
            _ => Err(Error::Relay("unexpected reply to ping".into())),
        }
    }

    async fn publish(&self, event: &RelayEvent) -> Result<()> {
        let message = ClientMessage::Publish {
            event: event.clone(),
        };
        match self.roundtrip(&message).await? {
            ServerMessage::Published => Ok(()),
            ServerMessage::Error { message } => Err(Error::Relay(message)),
            _ => Err(Error::Relay("unexpected reply to publish".into())),
        }
    }

    async fn subscribe(&self, mailbox: &[u8; 32], since: u64) -> Result<EventStream> {
        let url = self.ws_url(Some(mailbox), since)?;
        let socket = self.connect(&url).await?;
        Ok(event_stream(socket))
    }

    async fn subscribe_many(&self, mailboxes: &[[u8; 32]], since: u64) -> Result<EventStream> {
        if mailboxes.is_empty() {
            return Err(Error::Relay("no mailboxes requested".into()));
        }

        // Multiplexed subscription: one WebSocket, one `subscribe` message.
        // Keeps request URLs short even with thousands of rotating mailboxes.
        let url = self.ws_url(None, 0)?;
        let mut socket = self.connect(&url).await?;

        let message = ClientMessage::Subscribe {
            mailboxes: mailboxes.to_vec(),
            since,
        };
        let text = serde_json::to_string(&message)?;
        send_frame(&mut socket, Message::Text(text.into())).await?;

        Ok(event_stream(socket))
    }
}

fn event_stream<S>(socket: S) -> EventStream
where
    S: futures_util::Stream<
            Item = core::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Send
        + 'static,
{
    Box::pin(socket.filter_map(|message| async move {
        match message {
            Ok(Message::Text(text)) => match serde_json::from_str::<ServerMessage>(&text) {
                Ok(ServerMessage::Event { event }) => Some(Ok(event)),
                Ok(ServerMessage::Error { message }) => Some(Err(Error::Relay(message))),
                Ok(_) => None,
                Err(error) => Some(Err(Error::Json(error))),
            },
            Ok(Message::Close(_)) => None,
            Ok(_) => None,
            Err(error) => Some(Err(Error::Ws(error))),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_url_keeps_scheme_family() {
        let client = RelayClient::from_url("https://relay.example").unwrap();
        let url = client.ws_url(Some(&[0xAB; 32]), 42).unwrap();
        assert_eq!(url.scheme(), "wss");
        assert_eq!(url.path(), "/ws");
        assert!(url.query().unwrap().contains("mailbox=abab"));
        assert!(url.query().unwrap().contains("since=42"));

        let client = RelayClient::from_url("http://127.0.0.1:8080").unwrap();
        let url = client.ws_url(None, 0).unwrap();
        assert_eq!(url.scheme(), "ws");
        assert_eq!(url.as_str(), "ws://127.0.0.1:8080/ws");
    }

    #[test]
    fn rejects_unknown_scheme() {
        let client = RelayClient::from_url("ftp://relay.example").unwrap();
        assert!(client.ws_url(None, 0).is_err());
    }
}
