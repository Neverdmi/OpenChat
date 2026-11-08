//! Relay pool with randomized fan-out and fallback.

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::stream::{self, StreamExt};
use oc_core::random_array;
use oc_wire::RelayEvent;
use url::Url;

use crate::{Carrier, Error, EventStream, RelayClient, Result};

/// Delay before the first reconnect attempt.
const RECONNECT_INITIAL: Duration = Duration::from_millis(250);
/// Upper bound for the exponential reconnect delay.
const RECONNECT_MAX: Duration = Duration::from_secs(30);

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
        self.subscribe_many(core::slice::from_ref(mailbox), since)
            .await
    }

    /// Subscribe to several mailboxes through the first relay that accepts.
    pub async fn subscribe_many(&self, mailboxes: &[[u8; 32]], since: u64) -> Result<EventStream> {
        if self.relays.is_empty() {
            return Err(Error::NoRelay);
        }
        if mailboxes.is_empty() {
            return Err(Error::Relay("no mailboxes requested".into()));
        }

        let mut last_error = None;
        for index in pick_indices(self.relays.len(), self.relays.len()) {
            match self.relays[index].subscribe_many(mailboxes, since).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(Error::NoRelay))
    }

    /// Subscribe to several mailboxes through **every** relay and merge the
    /// streams. Duplicates are expected and must be dropped above this layer.
    ///
    /// Each relay stream is wrapped in an independent reconnect loop: a
    /// refused connection, a closed socket or a relay that comes back later
    /// never terminates the merged stream. This call itself cannot fail for
    /// network reasons; it only fails when no relay or mailbox is configured.
    pub async fn subscribe_all_many(
        &self,
        mailboxes: &[[u8; 32]],
        since: u64,
    ) -> Result<EventStream> {
        if self.relays.is_empty() {
            return Err(Error::NoRelay);
        }
        if mailboxes.is_empty() {
            return Err(Error::Relay("no mailboxes requested".into()));
        }

        let streams: Vec<EventStream> = self
            .relays
            .iter()
            .map(|relay| {
                reconnect_stream(Arc::clone(relay), mailboxes.to_vec(), since)
            })
            .collect();
        Ok(Box::pin(stream::select_all(streams)))
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

struct ReconnectState {
    carrier: Arc<dyn Carrier>,
    mailboxes: Vec<[u8; 32]>,
    since: u64,
    stream: Option<EventStream>,
    delay: Duration,
}

/// Wrap one carrier in an infinite reconnect loop.
///
/// The first subscription is attempted immediately. Failures and closed
/// streams are retried with exponential backoff, so the caller keeps a single
/// logical stream across network outages.
fn reconnect_stream(
    carrier: Arc<dyn Carrier>,
    mailboxes: Vec<[u8; 32]>,
    since: u64,
) -> EventStream {
    let state = ReconnectState {
        carrier,
        mailboxes,
        since,
        stream: None,
        delay: Duration::ZERO,
    };

    Box::pin(stream::unfold(state, |mut state| async move {
        loop {
            if state.stream.is_none() {
                if !state.delay.is_zero() {
                    tokio::time::sleep(state.delay).await;
                }
                match state
                    .carrier
                    .subscribe_many(&state.mailboxes, state.since)
                    .await
                {
                    Ok(subscription) => {
                        state.stream = Some(subscription);
                        state.delay = RECONNECT_INITIAL;
                    }
                    Err(_) => {
                        state.delay = next_delay(state.delay);
                        continue;
                    }
                }
            }

            let Some(subscription) = state.stream.as_mut() else {
                continue;
            };
            let next = subscription.next().await;
            match next {
                Some(Ok(event)) => return Some((Ok(event), state)),
                Some(Err(_)) | None => {
                    state.stream = None;
                    state.delay = next_delay(state.delay);
                }
            }
        }
    }))
}

fn next_delay(current: Duration) -> Duration {
    if current.is_zero() {
        RECONNECT_INITIAL
    } else {
        (current * 2).min(RECONNECT_MAX)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

    struct FlakyCarrier {
        url: Url,
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl Carrier for FlakyCarrier {
        fn endpoint(&self) -> &Url {
            &self.url
        }

        async fn health(&self) -> Result<()> {
            Ok(())
        }

        async fn publish(&self, _event: &RelayEvent) -> Result<()> {
            Ok(())
        }

        async fn subscribe(&self, mailbox: &[u8; 32], since: u64) -> Result<EventStream> {
            self.subscribe_many(core::slice::from_ref(mailbox), since)
                .await
        }

        async fn subscribe_many(
            &self,
            mailboxes: &[[u8; 32]],
            _since: u64,
        ) -> Result<EventStream> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                return Err(Error::Relay("offline".into()));
            }
            let event = RelayEvent::new(mailboxes[0], vec![1, 2, 3], 60);
            Ok(Box::pin(stream::iter(vec![Ok(event)])))
        }
    }

    #[tokio::test]
    async fn reconnect_stream_survives_initial_failures() {
        let carrier = Arc::new(FlakyCarrier {
            url: Url::parse("https://flaky.example").unwrap(),
            attempts: AtomicUsize::new(0),
        });
        let mut pool = RelayPool::new();
        pool.add(carrier.clone());

        let mut events = pool
            .subscribe_all_many(&[[7u8; 32]], 0)
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("reconnect should not time out")
            .expect("stream should stay open")
            .expect("event should decode");
        assert_eq!(event.mailbox, [7u8; 32]);
        assert!(carrier.attempts.load(Ordering::SeqCst) >= 3);
    }

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
