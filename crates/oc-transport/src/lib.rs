#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Transport layer for OpenChat.
//!
//! Every carrier is interchangeable: the protocol above it only needs
//! "publish an opaque event to a mailbox" and "stream events for a mailbox".

pub mod client;
pub mod error;
pub mod mqtt;
pub mod pool;
pub mod relay_list;
pub mod socks5;
pub mod ws;

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use oc_wire::RelayEvent;
use url::Url;

pub use client::RelayClient;
pub use error::{Error, Result};
pub use mqtt::MqttClient;
pub use pool::RelayPool;
pub use socks5::{TorConfig, TorMode};

/// Default timeout for transport operations.
pub(crate) const OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Stream of events delivered by a carrier.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<RelayEvent>> + Send>>;

/// One interchangeable transport path (a relay, later MQTT/WebRTC).
#[async_trait]
pub trait Carrier: Send + Sync {
    /// Base endpoint, used for diagnostics and relay lists.
    fn endpoint(&self) -> &Url;

    /// Check that the carrier is reachable.
    async fn health(&self) -> Result<()>;

    /// Publish one event.
    async fn publish(&self, event: &RelayEvent) -> Result<()>;

    /// Subscribe to a mailbox, replaying events newer than `since`.
    async fn subscribe(&self, mailbox: &[u8; 32], since: u64) -> Result<EventStream>;

    /// Subscribe to several mailboxes over one logical stream.
    ///
    /// The default implementation merges individual subscriptions, which is
    /// correct but opens one connection per mailbox. Carriers should override
    /// it when the protocol supports multiplexed subscriptions.
    async fn subscribe_many(&self, mailboxes: &[[u8; 32]], since: u64) -> Result<EventStream> {
        if mailboxes.is_empty() {
            return Err(Error::Relay("no mailboxes requested".into()));
        }

        let mut streams = Vec::with_capacity(mailboxes.len());
        for mailbox in mailboxes {
            streams.push(self.subscribe(mailbox, since).await?);
        }
        Ok(Box::pin(futures_util::stream::select_all(streams)))
    }
}
