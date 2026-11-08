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
    let summary = alice.add_invite(&invite, &pool, 1).await.unwrap();
    assert_eq!(summary.peer_id, bob_id);
    assert_eq!(summary.delivered, 1);

    // Bob processes the handshake and learns Alice's identity.
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert!(incoming.is_empty());
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
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].peer_id, alice_id);
    assert_eq!(incoming[0].msg_id, sent.msg_id);
    assert_eq!(incoming[0].text, "привет, боб");
    assert!(bob.contact(&alice_id).unwrap().verified);

    // Bob replies; Alice's ratchet performs its first DH ratchet.
    let reply = bob
        .send_text(&alice_id, "привет, алиса", &pool, 1)
        .await
        .unwrap();
    let incoming = alice
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].msg_id, reply.msg_id);
    assert_eq!(incoming[0].text, "привет, алиса");

    // Replaying stored relay events must not duplicate messages.
    let incoming = bob
        .listen_once(&pool, Duration::from_millis(500), 0)
        .await
        .unwrap();
    assert!(incoming.is_empty(), "duplicate delivery was not suppressed");
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
        assert_eq!(incoming[0].text, "before restart");

        bob.send_text(&alice_id, "ack", &pool, 1).await.unwrap();
        let incoming = alice
            .listen_once(&pool, Duration::from_millis(500), 0)
            .await
            .unwrap();
        assert_eq!(incoming[0].text, "ack");

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
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].text, "after restart");
}
