//! End-to-end test: two clients, one local relay, real WebSocket traffic.

use std::path::Path;
use std::time::Duration;

use oc_client::{Client, StateStore};
use oc_relay::{Relay, RelayConfig};
use oc_transport::RelayPool;
use tokio::net::TcpListener;

async fn start_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay = Relay::new(RelayConfig::default());
    tokio::spawn(async move {
        let _ = relay.serve(listener).await;
    });
    format!("http://{address}")
}

fn client(dir: &Path, passphrase: &str, relay: &str) -> Client {
    let store = StateStore::create(dir, passphrase).unwrap();
    Client::create(store, vec![relay.to_string()]).unwrap()
}

#[tokio::test]
async fn two_clients_exchange_text_through_a_relay() {
    let url = start_relay().await;
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &url);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &url);

    let alice_id = alice.peer_id().unwrap();
    let bob_id = bob.peer_id().unwrap();

    // Bob publishes an invite; Alice adds him and sends the handshake.
    let invite = bob.invite().unwrap();
    assert!(invite.starts_with("openchat://v1/"));
    // Short invite: Bob must publish his bundle before Alice can fetch it.
    bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
    let summary = alice.add_invite(&invite, &pool, 1).await.unwrap();
    assert_eq!(summary.peer_id, bob_id);
    assert_eq!(summary.delivered, 1);

    // Bob processes the handshake and learns Alice's identity.
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert!(incoming.messages.is_empty());
    assert_eq!(incoming.added_contacts, vec![alice_id]);
    assert!(bob.contact(&alice_id).is_some());
    assert!(!bob.contact(&alice_id).unwrap().verified);
    assert!(alice.contact(&bob_id).unwrap().verified);

    // Alice -> Bob.
    let sent = alice
        .send_text(&bob_id, "привет, боб", &pool, 1)
        .await
        .unwrap();
    assert_eq!(sent.delivered, 1);

    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].peer_id, alice_id);
    assert_eq!(incoming.messages[0].msg_id, sent.msg_id);
    assert_eq!(incoming.messages[0].text, "привет, боб");
    assert!(bob.contact(&alice_id).unwrap().verified);

    // Bob acknowledged the message; Alice sees the receipt.
    let acks = alice
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(acks.acks.len(), 1);
    assert_eq!(acks.acks[0].acked_msg_id, sent.msg_id);
    assert!(alice.is_acked(&bob_id, &sent.msg_id));

    // Bob replies; Alice's ratchet performs its first DH ratchet.
    let reply = bob
        .send_text(&alice_id, "привет, алиса", &pool, 1)
        .await
        .unwrap();
    let incoming = alice
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].msg_id, reply.msg_id);
    assert_eq!(incoming.messages[0].text, "привет, алиса");

    // Replaying stored relay events must not duplicate messages. Bob also
    // receives Alice's acknowledgement for his reply.
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert!(
        incoming.messages.is_empty(),
        "duplicate delivery was not suppressed"
    );
    assert_eq!(incoming.acks.len(), 1);
    assert_eq!(incoming.acks[0].acked_msg_id, reply.msg_id);
}

#[tokio::test]
async fn state_and_sessions_survive_restart() {
    let url = start_relay().await;
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice_pass = "alice-passphrase";
    let bob_pass = "bob-passphrase";

    let (alice_id, bob_id) = {
        let mut alice = client(alice_dir.path(), alice_pass, &url);
        let mut bob = client(bob_dir.path(), bob_pass, &url);
        let alice_id = alice.peer_id().unwrap();
        let bob_id = bob.peer_id().unwrap();

        let invite = bob.invite().unwrap();
        bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
        alice.add_invite(&invite, &pool, 1).await.unwrap();
        bob.listen_once(&pool, Duration::from_millis(500), 0)
            .await
            .unwrap();

        alice
            .send_text(&bob_id, "before restart", &pool, 1)
            .await
            .unwrap();
        let incoming = bob
            .listen_once(&pool, Duration::from_millis(500), 0)
            .await
            .unwrap();
        assert_eq!(incoming.messages[0].text, "before restart");

        bob.send_text(&alice_id, "ack", &pool, 1).await.unwrap();
        let incoming = alice
            .listen_once(&pool, Duration::from_millis(500), 0)
            .await
            .unwrap();
        assert_eq!(incoming.messages[0].text, "ack");

        (alice_id, bob_id)
    };

    // Both processes restart: reload encrypted state from disk.
    let mut alice = Client::open(StateStore::open(alice_dir.path(), alice_pass).unwrap()).unwrap();
    let mut bob = Client::open(StateStore::open(bob_dir.path(), bob_pass).unwrap()).unwrap();
    assert_eq!(alice.peer_id().unwrap(), alice_id);
    assert_eq!(bob.peer_id().unwrap(), bob_id);
    assert!(alice.contact(&bob_id).is_some());
    assert!(bob.contact(&alice_id).is_some());

    // The ratchet keeps working after the restart.
    alice
        .send_text(&bob_id, "after restart", &pool, 1)
        .await
        .unwrap();
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].text, "after restart");
}

#[tokio::test]
async fn multiple_relays_with_one_dead_still_deliver() {
    let live = start_relay().await;
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{address}")
    };
    let relays = vec![dead, live];
    let pool = RelayPool::from_urls(relays.clone()).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &relays[1]);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &relays[1]);
    let alice_id = alice.peer_id().unwrap();
    let bob_id = bob.peer_id().unwrap();

    let invite = bob.invite().unwrap();
    bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
    let summary = alice.add_invite(&invite, &pool, 2).await.unwrap();
    assert_eq!(summary.delivered, 1);
    assert!(!summary.queued);

    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.added_contacts, vec![alice_id]);

    let sent = alice
        .send_text(&bob_id, "through the live relay", &pool, 2)
        .await
        .unwrap();
    assert_eq!(sent.delivered, 1);
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].msg_id, sent.msg_id);
}

#[tokio::test]
async fn old_invites_still_work_after_prekey_rotation() {
    let url = start_relay().await;
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let carol_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &url);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &url);
    let mut carol = client(carol_dir.path(), "carol-passphrase", &url);

    let alice_id = alice.peer_id().unwrap();
    let bob_id = bob.peer_id().unwrap();
    let carol_id = carol.peer_id().unwrap();

    let old_invite = bob.invite_full().unwrap();
    bob.rotate_prekeys().unwrap();
    let new_invite = bob.invite_full().unwrap();
    assert_ne!(old_invite, new_invite);
    assert_eq!(bob.prekey_count(), 2);

    // Alice only has the pre-rotation invite.
    alice.add_invite(&old_invite, &pool, 1).await.unwrap();
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.added_contacts, vec![alice_id]);
    assert!(bob.contact(&alice_id).is_some());

    let sent = alice
        .send_text(&bob_id, "old invite", &pool, 1)
        .await
        .unwrap();
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].msg_id, sent.msg_id);

    // A fresh invite uses the new prekey and works in parallel.
    carol.add_invite(&new_invite, &pool, 1).await.unwrap();
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.added_contacts, vec![carol_id]);
    assert!(bob.contact(&carol_id).is_some());
}

#[tokio::test]
async fn listen_survives_relay_outage_and_messages_are_redelivered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}");
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = Relay::new(RelayConfig::default())
            .serve_until(listener, async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &url);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &url);
    let bob_id = bob.peer_id().unwrap();
    let alice_id = alice.peer_id().unwrap();

    let invite = bob.invite().unwrap();
    bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
    alice.add_invite(&invite, &pool, 1).await.unwrap();
    bob.listen_once(&pool, Duration::from_millis(400), 0)
        .await
        .unwrap();
    assert!(bob.contact(&alice_id).is_some());

    // Stop the relay and wait until the listener is really gone.
    shutdown_tx.send(()).unwrap();
    server.await.unwrap();

    let sent = alice
        .send_text(&bob_id, "during outage", &pool, 1)
        .await
        .unwrap();
    assert!(sent.queued);

    // A listen pass during the outage must return cleanly, not fail.
    let idle = bob
        .listen_once(&pool, Duration::from_millis(400), 0)
        .await
        .unwrap();
    assert!(idle.messages.is_empty());

    // Bring the relay back on the same address.
    let listener = TcpListener::bind(address).await.unwrap();
    let relay = Relay::new(RelayConfig::default());
    tokio::spawn(async move {
        let _ = relay.serve(listener).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(alice.flush_outbox(&pool, 1).await.unwrap(), 1);
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].msg_id, sent.msg_id);
    assert_eq!(incoming.messages[0].text, "during outage");
}

#[tokio::test]
async fn offline_messages_deliver_and_are_acknowledged_after_reconnect() {
    // Reserve a port, then release it so the first publishes hit a closed
    // port instead of a hanging server.
    let address = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let url = format!("http://{address}");
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &url);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &url);

    let alice_id = alice.peer_id().unwrap();
    let bob_id = bob.peer_id().unwrap();

    // Relay is down: both the handshake and the text stay in the outbox.
    // A full invite is used here because a short invite would need a
    // live relay to fetch the bundle from.
    let invite = bob.invite_full().unwrap();
    let summary = alice.add_invite(&invite, &pool, 1).await.unwrap();
    assert!(summary.queued);
    assert_eq!(alice.outbox().len(), 1);

    let sent = alice
        .send_text(&bob_id, "offline hello", &pool, 1)
        .await
        .unwrap();
    assert!(sent.queued);
    assert_eq!(alice.outbox().len(), 2);

    // Network returns.
    let listener = TcpListener::bind(address).await.unwrap();
    let relay = Relay::new(RelayConfig::default());
    tokio::spawn(async move {
        let _ = relay.serve(listener).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let delivered = alice.flush_outbox(&pool, 1).await.unwrap();
    assert_eq!(delivered, 2);
    assert!(alice.outbox().is_empty());

    // Bob processes the handshake, then the text from the same replay.
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.added_contacts, vec![alice_id]);
    assert_eq!(incoming.messages.len(), 1);
    assert_eq!(incoming.messages[0].text, "offline hello");
    assert_eq!(incoming.messages[0].msg_id, sent.msg_id);

    // Bob's acknowledgement reaches Alice.
    let incoming = alice
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.acks.len(), 1);
    assert_eq!(incoming.acks[0].acked_msg_id, sent.msg_id);
    assert!(alice.is_acked(&bob_id, &sent.msg_id));
}

#[tokio::test]
async fn webrtc_data_channel_establishes_between_online_peers() {
    let url = start_relay().await;
    let pool = RelayPool::from_urls([url.clone()]).unwrap();

    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let mut alice = client(alice_dir.path(), "alice-passphrase", &url);
    let mut bob = client(bob_dir.path(), "bob-passphrase", &url);
    alice.set_webrtc(true);
    bob.set_webrtc(true);

    let bob_id = bob.peer_id().unwrap();

    // Short invite flow first (bundle fetch), then the handshake.
    let invite = bob.invite().unwrap();
    bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
    alice.add_invite(&invite, &pool, 1).await.unwrap();
    bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();

    // Alice's first send starts WebRTC negotiation (offer via relay
    // signaling) and falls back to relay delivery for this message.
    alice.send_text(&bob_id, "first via relay", &pool, 1).await.unwrap();
    // Bob answers (offer -> answer via signaling), Alice completes ICE.
    for _ in 0..10 {
        bob.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
        alice.listen_once(&pool, Duration::from_millis(500), 0).await.unwrap();
        if alice.webrtc_session_open(&bob_id).await {
            break;
        }
    }
    assert!(
        alice.webrtc_session_open(&bob_id).await,
        "WebRTC data channel should open between the two peers"
    );

    // The next message goes over the direct data channel.
    alice
        .send_text(&bob_id, "second via webrtc", &pool, 1)
        .await
        .unwrap();
    let mut received = false;
    for _ in 0..10 {
        let outcome = bob
            .listen_once(&pool, Duration::from_millis(500), 0)
            .await
            .unwrap();
        if outcome.messages.iter().any(|m| m.text == "second via webrtc") {
            received = true;
            break;
        }
    }
    assert!(received, "bob should receive the WebRTC-delivered text");
}
