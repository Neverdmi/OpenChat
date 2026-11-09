//! End-to-end tests: real relay over a real WebSocket connection.

use std::time::Duration;

use futures_util::StreamExt;
use oc_relay::{Relay, RelayConfig};
use oc_transport::{Carrier, RelayClient, RelayPool};
use oc_wire::RelayEvent;
use tokio::net::TcpListener;

async fn start_relay(config: RelayConfig) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay = Relay::new(config);
    tokio::spawn(async move {
        let _ = relay.serve(listener).await;
    });
    format!("http://{address}")
}

#[tokio::test]
async fn publish_and_subscribe_roundtrip() {
    let url = start_relay(RelayConfig::default()).await;
    let client = RelayClient::from_url(&url).unwrap();

    client.health().await.unwrap();

    let mailbox = [7u8; 32];
    let event = RelayEvent::new(mailbox, b"opaque-ciphertext".to_vec(), 3600);
    client.publish(&event).await.unwrap();

    let mut stream = client.subscribe(&mailbox, 0).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for event")
        .expect("stream ended")
        .expect("relay error");

    assert_eq!(received.mailbox, mailbox);
    assert_eq!(received.payload, b"opaque-ciphertext");
}

#[tokio::test]
async fn live_event_is_delivered_to_an_open_subscription() {
    let url = start_relay(RelayConfig::default()).await;
    let client = RelayClient::from_url(&url).unwrap();

    let mailbox = [3u8; 32];
    let mut stream = client.subscribe(&mailbox, 0).await.unwrap();

    let event = RelayEvent::new(mailbox, b"live".to_vec(), 3600);
    client.publish(&event).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for live event")
        .expect("stream ended")
        .expect("relay error");
    assert_eq!(received.payload, b"live");
}

#[tokio::test]
async fn other_mailboxes_are_not_delivered() {
    let url = start_relay(RelayConfig::default()).await;
    let client = RelayClient::from_url(&url).unwrap();

    let mine = [1u8; 32];
    let other = [2u8; 32];
    let mut stream = client.subscribe(&mine, 0).await.unwrap();

    let event = RelayEvent::new(other, b"not-mine".to_vec(), 3600);
    client.publish(&event).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;
    assert!(result.is_err(), "event leaked to a different mailbox");
}

#[tokio::test]
async fn limits_are_enforced() {
    let config = RelayConfig {
        max_payload_bytes: 32,
        ..RelayConfig::default()
    };
    let url = start_relay(config).await;
    let client = RelayClient::from_url(&url).unwrap();

    let too_big = RelayEvent::new([4u8; 32], vec![0u8; 33], 3600);
    assert!(client.publish(&too_big).await.is_err());

    let expired = RelayEvent {
        mailbox: [5u8; 32],
        created_at: 1,
        expires_at: 2,
        payload: vec![1, 2, 3],
    };
    assert!(client.publish(&expired).await.is_err());
}

#[tokio::test]
async fn multiple_mailboxes_share_one_subscription() {
    let url = start_relay(RelayConfig::default()).await;
    let client = RelayClient::from_url(&url).unwrap();

    let first = [10u8; 32];
    let second = [11u8; 32];
    let mut stream = client.subscribe_many(&[first, second], 0).await.unwrap();

    let event_a = RelayEvent::new(first, b"one".to_vec(), 3600);
    let event_b = RelayEvent::new(second, b"two".to_vec(), 3600);
    client.publish(&event_a).await.unwrap();
    client.publish(&event_b).await.unwrap();

    let mut received = Vec::new();
    while received.len() < 2 {
        let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for events")
            .expect("stream ended")
            .expect("relay error");
        received.push(event.payload);
    }
    received.sort();
    assert_eq!(received, vec![b"one".to_vec(), b"two".to_vec()]);
}

#[tokio::test]
async fn pool_publishes_to_a_relay() {
    let url = start_relay(RelayConfig::default()).await;
    let pool = RelayPool::from_urls([url]).unwrap();
    assert_eq!(pool.len(), 1);

    let mailbox = [8u8; 32];
    let event = RelayEvent::new(mailbox, b"via-pool".to_vec(), 3600);
    let delivered = pool.publish(&event, 3).await.unwrap();
    assert_eq!(delivered, 1);

    let mut stream = pool.subscribe(&mailbox, 0).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("relay error");
    assert_eq!(received.payload, b"via-pool");
}

#[tokio::test]
async fn global_event_cap_evicts_oldest_mailboxes() {
    let config = RelayConfig {
        max_total_events: 10,
        max_mailboxes: 100,
        max_total_bytes: 10 * 1024 * 1024,
        ..RelayConfig::default()
    };
    let url = start_relay(config).await;
    let client = RelayClient::from_url(&url).unwrap();

    // Fill 20 mailboxes with one event each; only the newest 10 survive.
    for index in 0..20u8 {
        let mailbox = [index + 1; 32];
        client
            .publish(&RelayEvent::new(mailbox, b"data".to_vec(), 3600))
            .await
            .unwrap();
    }

    // The oldest mailbox (1) was evicted; the newest (20) still replays.
    let mut fresh = client
        .subscribe(&[1u8; 32], 0)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), fresh.next())
            .await
            .is_err(),
        "oldest mailbox should have been evicted"
    );
    let mut fresh = client
        .subscribe(&[20u8; 32], 0)
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), fresh.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("relay error");
    assert_eq!(received.payload, b"data");
}

#[tokio::test]
async fn publish_rate_limit_rejects_flood() {
    let url = start_relay(RelayConfig::default()).await;
    let client = RelayClient::from_url(&url).unwrap();

    let mut accepted = 0;
    for index in 0..200u8 {
        let mailbox = [index.wrapping_add(1); 32];
        if client
            .publish(&RelayEvent::new(mailbox, vec![1u8; 64], 3600))
            .await
            .is_ok()
        {
            accepted += 1;
        }
    }
    assert!(
        accepted <= 130,
        "rate limiter should reject most of the flood (accepted {accepted})"
    );
}
