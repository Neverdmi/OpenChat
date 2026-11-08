//! Relay pool with randomized fan-out and fallback.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::stream::{self, StreamExt};
use oc_core::random_array;
use oc_wire::RelayEvent;
use url::Url;

use crate::{Carrier, Error, EventStream, MqttClient, RelayClient, Result};

/// Delay before the first reconnect attempt.
const RECONNECT_INITIAL: Duration = Duration::from_millis(250);
/// Upper bound for the exponential reconnect delay.
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Consecutive failures after which a relay is temporarily deprioritised.
const MAX_CONSECUTIVE_FAILURES: u32 = 2;

struct PoolEntry {
    carrier: Arc<dyn Carrier>,
    failures: AtomicU32,
}

impl PoolEntry {
    fn new(carrier: Arc<dyn Carrier>) -> Self {
        Self {
            carrier,
            failures: AtomicU32::new(0),
        }
    }

    fn healthy(&self) -> bool {
        self.failures.load(Ordering::Relaxed) < MAX_CONSECUTIVE_FAILURES
    }

    fn succeeded(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// A set of interchangeable relays.
#[derive(Default)]
pub struct RelayPool {
    relays: Vec<PoolEntry>,
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
    ///
    /// `mqtts://`/`mqtt://` endpoints become an MQTT-over-WSS carrier and
    /// `mqtttls://` an MQTT-over-native-TLS carrier ([`MqttClient`]);
    /// everything else is a WebSocket relay ([`RelayClient`]). All are
    /// interchangeable in the pool, so one [`RelayPool`] can mix carriers.
    pub fn add_url(&mut self, url: &str) -> Result<()> {
        let parsed = Url::parse(url).map_err(|error| Error::Url(error.to_string()))?;
        match parsed.scheme() {
            "mqtts" | "mqtt" | "mqtttls" => self.add(Arc::new(MqttClient::new(parsed))),
            _ => self.add(Arc::new(RelayClient::new(parsed))),
        }
        Ok(())
    }

    /// Add a pre-built carrier.
    pub fn add(&mut self, carrier: Arc<dyn Carrier>) {
        self.relays.push(PoolEntry::new(carrier));
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
        self.relays
            .iter()
            .map(|entry| entry.carrier.endpoint())
            .collect()
    }

    /// Number of relays currently considered healthy.
    pub fn healthy_count(&self) -> usize {
        self.relays.iter().filter(|entry| entry.healthy()).count()
    }

    /// Publish to up to `fanout` randomly chosen relays.
    ///
    /// Succeeds if at least one relay accepted the event; returns the number
    /// of successful deliveries.
    pub async fn publish(&self, event: &RelayEvent, fanout: usize) -> Result<usize> {
        if self.relays.is_empty() {
            return Err(Error::NoRelay);
        }

        let indices = self.pick_fanout(fanout.max(1));
        let futures = indices.iter().map(|&index| {
            let relay = Arc::clone(&self.relays[index].carrier);
            let event = event.clone();
            async move { relay.publish(&event).await }
        });

        let results = join_all(futures).await;
        let mut successes = 0;
        for (&index, result) in indices.iter().zip(&results) {
            if result.is_ok() {
                self.relays[index].succeeded();
                successes += 1;
            } else {
                self.relays[index].failed();
            }
        }
        if successes == 0 {
            return Err(Error::NoRelay);
        }
        Ok(successes)
    }

    /// Pick healthy relays first, falling back to all relays when every
    /// candidate has been marked dead (so recovered relays get another
    /// chance without an explicit health check).
    fn pick_fanout(&self, count: usize) -> Vec<usize> {
        let healthy: Vec<usize> = self
            .relays
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.healthy())
            .map(|(index, _)| index)
            .collect();
        if healthy.is_empty() {
            pick_indices(self.relays.len(), count)
        } else {
            pick_from(&healthy, count)
        }
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
            match self.relays[index]
                .carrier
                .subscribe_many(mailboxes, since)
                .await
            {
                Ok(stream) => {
                    self.relays[index].succeeded();
                    return Ok(stream);
                }
                Err(error) => {
                    self.relays[index].failed();
                    last_error = Some(error);
                }
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
            .map(|entry| {
                reconnect_stream(Arc::clone(&entry.carrier), mailboxes.to_vec(), since)
            })
            .collect();
        Ok(Box::pin(stream::select_all(streams)))
    }

    /// Health-check every relay and refresh the dead-relay cache.
    pub async fn health(&self) -> Vec<(String, bool)> {
        let futures = self.relays.iter().map(|entry| {
            let carrier = Arc::clone(&entry.carrier);
            async move {
                let healthy = carrier.health().await.is_ok();
                (carrier.endpoint().to_string(), healthy)
            }
        });
        let results = join_all(futures).await;
        for (entry, (_, healthy)) in self.relays.iter().zip(&results) {
            if *healthy {
                entry.succeeded();
            } else {
                entry.failed();
            }
        }
        results
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

/// Pick `count` unique entries from a candidate list, rotated by a random
/// offset.
fn pick_from(candidates: &[usize], count: usize) -> Vec<usize> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let count = count.min(candidates.len());
    let offset = u32::from_le_bytes(random_array::<4>()) as usize % candidates.len();
    (0..count)
        .map(|index| candidates[(offset + index) % candidates.len()])
        .collect()
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

    struct PublishMock {
        url: Url,
        attempts: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl Carrier for PublishMock {
        fn endpoint(&self) -> &Url {
            &self.url
        }

        async fn health(&self) -> Result<()> {
            Ok(())
        }

        async fn publish(&self, _event: &RelayEvent) -> Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(Error::Relay("unreachable".into()))
            } else {
                Ok(())
            }
        }

        async fn subscribe(&self, _mailbox: &[u8; 32], _since: u64) -> Result<EventStream> {
            Err(Error::Relay("not used".into()))
        }
    }

    #[tokio::test]
    async fn dead_relays_are_deprioritised_after_failures() {
        let good = Arc::new(PublishMock {
            url: Url::parse("https://good.example").unwrap(),
            attempts: AtomicUsize::new(0),
            fail: false,
        });
        let bad = Arc::new(PublishMock {
            url: Url::parse("https://bad.example").unwrap(),
            attempts: AtomicUsize::new(0),
            fail: true,
        });
        let mut pool = RelayPool::new();
        pool.add(bad.clone());
        pool.add(good.clone());

        let event = RelayEvent::new([0u8; 32], vec![1], 60);
        for _ in 0..4 {
            assert_eq!(pool.publish(&event, 2).await.unwrap(), 1);
        }
        assert_eq!(
            bad.attempts.load(Ordering::SeqCst),
            MAX_CONSECUTIVE_FAILURES as usize
        );
        assert_eq!(good.attempts.load(Ordering::SeqCst), 4);
        assert_eq!(pool.healthy_count(), 1);
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

    #[test]
    fn mqtt_urls_dispatch_to_mqtt_carrier() {
        let mut pool = RelayPool::new();
        pool.add_url("mqtts://broker.example/mqtt").unwrap();
        pool.add_url("mqtt://broker.example:1883/mqtt").unwrap();
        pool.add_url("mqtttls://broker.example:8883").unwrap();
        assert_eq!(pool.len(), 3);
        let schemes: Vec<&str> = pool
            .endpoints()
            .iter()
            .map(|url| url.scheme())
            .collect();
        assert_eq!(schemes, vec!["mqtts", "mqtt", "mqtttls"]);
    }
}
