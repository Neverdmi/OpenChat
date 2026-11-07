#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Transport layer for OpenChat.
//!
//! Every carrier is interchangeable: the protocol above it only needs
//! "publish an opaque event to a mailbox" and "stream events for a mailbox".

pub mod client;
pub mod error;
pub mod pool;
pub mod relay_list;

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use oc_wire::RelayEvent;
use url::Url;

pub use client::RelayClient;
pub use error::{Error, Result};
pub use pool::RelayPool;

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
}
