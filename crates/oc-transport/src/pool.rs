//! Relay pool with randomized fan-out and fallback.

use std::sync::Arc;

use futures_util::future::join_all;
use oc_core::random_array;
use oc_wire::RelayEvent;
use url::Url;

use crate::{Carrier, Error, EventStream, RelayClient, Result};

/// A set of interchangeable relays.
#[derive(Default)]
pub struct RelayPool {
    relays: Vec<Arc<dyn Carrier>>,
}

impl RelayPool {
    /// Empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a pool from relay URL strings.
    pub fn from_urls<I>(urls: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut pool = Self::new();
        for url in urls {
            pool.add_url(&url)?;
        }
        Ok(pool)
    }

    /// Add a relay by URL.
    pub fn add_url(&mut self, url: &str) -> Result<()> {
        let client = RelayClient::from_url(url)?;
        self.relays.push(Arc::new(client));
        Ok(())
    }

    /// Add a pre-built carrier.
    pub fn add(&mut self, carrier: Arc<dyn Carrier>) {
        self.relays.push(carrier);
    }

    /// Number of relays.
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Endpoints of all relays.
    pub fn endpoints(&self) -> Vec<&Url> {
        self.relays.iter().map(|relay| relay.endpoint()).collect()
    }

    /// Publish to up to `fanout` randomly chosen relays.
    ///
    /// Succeeds if at least one relay accepted the event; returns the number
    /// of successful deliveries.
    pub async fn publish(&self, event: &RelayEvent, fanout: usize) -> Result<usize> {
        if self.relays.is_empty() {
            return Err(Error::NoRelay);
        }

        let indices = pick_indices(self.relays.len(), fanout.max(1));
        let futures = indices.into_iter().map(|index| {
            let relay = Arc::clone(&self.relays[index]);
            let event = event.clone();
            async move { relay.publish(&event).await }
        });

        let results = join_all(futures).await;
        let successes = results.iter().filter(|result| result.is_ok()).count();
        if successes == 0 {
            return Err(Error::NoRelay);
        }
        Ok(successes)
    }

    /// Subscribe through the first relay that accepts the connection.
    pub async fn subscribe(&self, mailbox: &[u8; 32], since: u64) -> Result<EventStream> {
        if self.relays.is_empty() {
            return Err(Error::NoRelay);
        }

        let mut last_error = None;
        for index in pick_indices(self.relays.len(), self.relays.len()) {
            match self.relays[index].subscribe(mailbox, since).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(Error::NoRelay))
    }

    /// Health-check every relay.
    pub async fn health(&self) -> Vec<(String, bool)> {
        let futures = self.relays.iter().map(|relay| {
            let relay = Arc::clone(relay);
            async move {
                let healthy = relay.health().await.is_ok();
                (relay.endpoint().to_string(), healthy)
            }
        });
        join_all(futures).await
    }
}

/// Pick `count` unique indices, rotated by a random offset.
fn pick_indices(len: usize, count: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let count = count.min(len);
    let offset = u32::from_le_bytes(random_array::<4>()) as usize % len;
    (0..count).map(|index| (offset + index) % len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picking_is_unique_and_in_range() {
        for _ in 0..20 {
            let indices = pick_indices(10, 5);
            assert_eq!(indices.len(), 5);
            let mut sorted = indices.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 5);
            assert!(indices.iter().all(|index| *index < 10));
        }
    }

    #[tokio::test]
    async fn empty_pool_fails_cleanly() {
        let pool = RelayPool::new();
        assert!(pool.is_empty());
        assert!(matches!(
            pool.publish(&RelayEvent::new([0u8; 32], vec![1], 60), 3)
                .await,
            Err(Error::NoRelay)
        ));
    }

    #[test]
    fn url_validation() {
        let mut pool = RelayPool::new();
        pool.add_url("https://relay.example").unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.add_url("not a url").is_err());
    }
}
