//! Double Ratchet with per-message forward secrecy.
//!
//! Follows the Signal Double Ratchet specification:
//! `KDF_RK` uses HKDF-SHA256, `KDF_CK` uses HMAC-SHA256 with the standard
//! `0x01`/`0x02` constants, and messages are encrypted with
//! XChaCha20-Poly1305.
//!
//! The handshake transcript is bound into every AEAD's associated data.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::aead;
use crate::kdf::hkdf64;
use crate::x3dh::ratchet_root;
use crate::{Error, Result, random_array};

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of message keys kept for out-of-order delivery.
pub const MAX_SKIP: u32 = 1000;
/// Serialized header length: DH public key (32) + `pn` (4) + `n` (4).
pub const HEADER_LEN: usize = 40;

const RATCHET_DOMAIN: &[u8] = b"openchat/ratchet/v1";
const ROOT_INFO: &[u8] = b"openchat/ratchet-rk/v1";

/// Ratchet message header. Sent in clear next to the ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Sender's current ratchet public key.
    pub dh: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub pn: u32,
    /// Number of this message in the current sending chain.
    pub n: u32,
}

impl Header {
    /// Serialize to 40 bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    /// Parse from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::InvalidLength);
        }
        let dh = bytes[..32].try_into().expect("length checked");
        let pn = u32::from_le_bytes(bytes[32..36].try_into().expect("length checked"));
        let n = u32::from_le_bytes(bytes[36..40].try_into().expect("length checked"));
        Ok(Self { dh, pn, n })
    }
}

struct ChainKey {
    key: [u8; 32],
}

impl ChainKey {
    fn next(&mut self) -> [u8; 32] {
        let (next, message_key) = kdf_chain(&self.key);
        self.key = next;
        message_key
    }
}

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let next = hmac_sha256(chain_key, &[0x02]);
    let message_key = hmac_sha256(chain_key, &[0x01]);
    (next, message_key)
}

fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf64(root_key, dh_output, ROOT_INFO);
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    (root, chain)
}

/// One skipped message key, exported for encrypted state persistence.
#[derive(Clone, Serialize, Deserialize)]
pub struct SkippedKey {
    /// Ratchet public key of the remote chain.
    pub dh: [u8; 32],
    /// Message number within that chain.
    pub n: u32,
    /// Derived message key.
    pub key: [u8; 32],
}

/// Serializable snapshot of a [`Ratchet`].
///
/// Contains secret key material. Only write it to encrypted storage.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetSnapshot {
    /// Root key.
    pub root_key: [u8; 32],
    /// Local ratchet secret.
    pub self_dh: [u8; 32],
    /// Local ratchet public key.
    pub self_dh_public: [u8; 32],
    /// Remote ratchet public key, once known.
    pub remote_dh: Option<[u8; 32]>,
    /// Sending chain key, once a sending chain exists.
    pub send_chain: Option<[u8; 32]>,
    /// Receiving chain key, once a receiving chain exists.
    pub recv_chain: Option<[u8; 32]>,
    /// Messages sent in the current chain.
    pub send_count: u32,
    /// Messages sent in the previous chain.
    pub prev_send_count: u32,
    /// Messages received in the current chain.
    pub recv_count: u32,
    /// Keys retained for out-of-order delivery.
    pub skipped: Vec<SkippedKey>,
    /// Handshake transcript bound into AEAD associated data.
    pub transcript: Vec<u8>,
    /// Maximum number of skipped keys.
    pub max_skip: u32,
}

impl core::fmt::Debug for RatchetSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetSnapshot")
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("skipped", &self.skipped.len())
            .field("remote_dh", &self.remote_dh.map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

/// Rollback snapshot of the mutable ratchet state.
struct StateBackup {
    root_key: [u8; 32],
    self_dh: [u8; 32],
    self_dh_public: [u8; 32],
    remote_dh: Option<[u8; 32]>,
    send_chain: Option<[u8; 32]>,
    recv_chain: Option<[u8; 32]>,
    send_count: u32,
    prev_send_count: u32,
    recv_count: u32,
    skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
}

/// Per-session Double Ratchet state.
pub struct Ratchet {
    root_key: [u8; 32],
    self_dh: StaticSecret,
    self_dh_public: [u8; 32],
    remote_dh: Option<[u8; 32]>,
    send_chain: Option<ChainKey>,
    recv_chain: Option<ChainKey>,
    send_count: u32,
    prev_send_count: u32,
    recv_count: u32,
    skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
    transcript: Vec<u8>,
    max_skip: u32,
}

impl core::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ratchet")
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("remote_dh", &self.remote_dh.map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl Ratchet {
    /// Initialize the initiating side.
    ///
    /// `remote_ratchet` is the responder's signed prekey, which doubles as
    /// the initial ratchet public key.
    pub fn new_initiator(
        session_key: &[u8; 32],
        remote_ratchet: &[u8; 32],
        transcript: Vec<u8>,
    ) -> Self {
        let root_key = ratchet_root(session_key);
        let self_dh = StaticSecret::from(random_array::<32>());
        let self_dh_public = PublicKey::from(&self_dh).to_bytes();

        let shared = self_dh
            .diffie_hellman(&PublicKey::from(*remote_ratchet))
            .to_bytes();
        let (root_key, send_chain) = kdf_root(&root_key, &shared);

        Self {
            root_key,
            self_dh,
            self_dh_public,
            remote_dh: Some(*remote_ratchet),
            send_chain: Some(ChainKey { key: send_chain }),
            recv_chain: None,
            send_count: 0,
            prev_send_count: 0,
            recv_count: 0,
            skipped: BTreeMap::new(),
            transcript,
            max_skip: MAX_SKIP,
        }
    }

    /// Initialize the responding side.
    ///
    /// `self_dh` must be the same signed prekey that was published in the
    /// bundle (and used for X3DH).
    pub fn new_responder(
        session_key: &[u8; 32],
        self_dh: StaticSecret,
        transcript: Vec<u8>,
    ) -> Self {
        let root_key = ratchet_root(session_key);
        let self_dh_public = PublicKey::from(&self_dh).to_bytes();

        Self {
            root_key,
            self_dh,
            self_dh_public,
            remote_dh: None,
            send_chain: None,
            recv_chain: None,
            send_count: 0,
            prev_send_count: 0,
            recv_count: 0,
            skipped: BTreeMap::new(),
            transcript,
            max_skip: MAX_SKIP,
        }
    }

    /// Export the complete ratchet state for encrypted persistence.
    pub fn snapshot(&self) -> RatchetSnapshot {
        RatchetSnapshot {
            root_key: self.root_key,
            self_dh: self.self_dh.to_bytes(),
            self_dh_public: self.self_dh_public,
            remote_dh: self.remote_dh,
            send_chain: self.send_chain.as_ref().map(|chain| chain.key),
            recv_chain: self.recv_chain.as_ref().map(|chain| chain.key),
            send_count: self.send_count,
            prev_send_count: self.prev_send_count,
            recv_count: self.recv_count,
            skipped: self
                .skipped
                .iter()
                .map(|((dh, n), key)| SkippedKey {
                    dh: *dh,
                    n: *n,
                    key: *key,
                })
                .collect(),
            transcript: self.transcript.clone(),
            max_skip: self.max_skip,
        }
    }

    /// Restore a ratchet from [`Ratchet::snapshot`].
    pub fn from_snapshot(snapshot: RatchetSnapshot) -> Result<Self> {
        if snapshot.max_skip == 0 || snapshot.max_skip > MAX_SKIP {
            return Err(Error::RatchetState);
        }
        if snapshot.skipped.len() > snapshot.max_skip as usize {
            return Err(Error::TooManySkipped);
        }
        if snapshot.remote_dh.is_none()
            && (snapshot.send_chain.is_some() || snapshot.recv_chain.is_some())
        {
            return Err(Error::RatchetState);
        }

        let self_dh = StaticSecret::from(snapshot.self_dh);
        if PublicKey::from(&self_dh).to_bytes() != snapshot.self_dh_public {
            return Err(Error::InvalidKey);
        }

        let mut skipped = BTreeMap::new();
        for entry in snapshot.skipped {
            skipped.insert((entry.dh, entry.n), entry.key);
        }

        Ok(Self {
            root_key: snapshot.root_key,
            self_dh,
            self_dh_public: snapshot.self_dh_public,
            remote_dh: snapshot.remote_dh,
            send_chain: snapshot.send_chain.map(|key| ChainKey { key }),
            recv_chain: snapshot.recv_chain.map(|key| ChainKey { key }),
            send_count: snapshot.send_count,
            prev_send_count: snapshot.prev_send_count,
            recv_count: snapshot.recv_count,
            skipped,
            transcript: snapshot.transcript,
            max_skip: snapshot.max_skip,
        })
    }

    /// Encrypt one message, returning its header and wire bytes.
    ///
    /// Wire format: `nonce(24) || ciphertext`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>)> {
        let header = Header {
            dh: self.self_dh_public,
            pn: self.prev_send_count,
            n: self.send_count,
        };

        let chain = self.send_chain.as_mut().ok_or(Error::RatchetState)?;
        let message_key = chain.next();
        self.send_count = self.send_count.checked_add(1).ok_or(Error::RatchetState)?;

        let aad = self.associated_data(&header);
        let nonce = random_array::<{ aead::NONCE_LEN }>();
        let ciphertext = aead::encrypt(&message_key, &nonce, &aad, plaintext)?;

        let mut wire = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        Ok((header, wire))
    }

    /// Decrypt one message.
    ///
    /// The AEAD tag authenticates the message, so no ratchet state is
    /// mutated before it verifies: on any failure the state is restored
    /// to the pre-decrypt snapshot (libsignal-style rollback). A forged
    /// or replayed frame therefore cannot desynchronize the session —
    /// the sealed envelope gives the attacker chosen headers, but not
    /// valid tags.
    pub fn decrypt(&mut self, header: &Header, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < aead::NONCE_LEN + aead::TAG_LEN {
            return Err(Error::InvalidLength);
        }

        let nonce: [u8; aead::NONCE_LEN] =
            wire[..aead::NONCE_LEN].try_into().expect("length checked");
        let ciphertext = &wire[aead::NONCE_LEN..];
        let aad = self.associated_data(header);

        // Skipped key (out-of-order delivery): try it without consuming
        // it first; only a successful decrypt removes it.
        if let Some(message_key) = self.skipped.get(&(header.dh, header.n)).copied() {
            let plaintext = aead::decrypt(&message_key, &nonce, &aad, ciphertext)?;
            if let Some(mut used) = self.skipped.remove(&(header.dh, header.n)) {
                used.zeroize();
            }
            return Ok(plaintext);
        }

        // Replay on the current chain: `n` below the receive counter
        // with no skipped key means this message was already consumed.
        // Rejecting it here (instead of advancing the chain with the
        // next key) keeps forged replays from desynchronizing us.
        if self.remote_dh == Some(header.dh) && header.n < self.recv_count {
            return Err(Error::Replay);
        }

        let backup = self.backup();
        let result = self.decrypt_inner(header, &nonce, ciphertext, &aad);
        if result.is_err() {
            self.restore(backup);
        }
        result
    }

    /// Decrypt with state mutation; caller guarantees rollback on error.
    fn decrypt_inner(
        &mut self,
        header: &Header,
        nonce: &[u8; aead::NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if self.remote_dh != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }

        self.skip_message_keys(header.n)?;

        let chain = self.recv_chain.as_mut().ok_or(Error::RatchetState)?;
        let message_key = chain.next();
        self.recv_count = self.recv_count.checked_add(1).ok_or(Error::RatchetState)?;

        aead::decrypt(&message_key, nonce, aad, ciphertext)
    }

    /// Snapshot of every mutable field, for rollback on decrypt failure.
    fn backup(&self) -> StateBackup {
        StateBackup {
            root_key: self.root_key,
            self_dh: self.self_dh.to_bytes(),
            self_dh_public: self.self_dh_public,
            remote_dh: self.remote_dh,
            send_chain: self.send_chain.as_ref().map(|chain| chain.key),
            recv_chain: self.recv_chain.as_ref().map(|chain| chain.key),
            send_count: self.send_count,
            prev_send_count: self.prev_send_count,
            recv_count: self.recv_count,
            skipped: self.skipped.clone(),
        }
    }

    /// Restore a backup taken by [`Ratchet::backup`].
    fn restore(&mut self, backup: StateBackup) {
        self.root_key = backup.root_key;
        self.self_dh = StaticSecret::from(backup.self_dh);
        self.self_dh_public = backup.self_dh_public;
        self.remote_dh = backup.remote_dh;
        self.send_chain = backup.send_chain.map(|key| ChainKey { key });
        self.recv_chain = backup.recv_chain.map(|key| ChainKey { key });
        self.send_count = backup.send_count;
        self.prev_send_count = backup.prev_send_count;
        self.recv_count = backup.recv_count;
        self.skipped = backup.skipped;
    }

    fn associated_data(&self, header: &Header) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.transcript.len() + RATCHET_DOMAIN.len() + HEADER_LEN);
        aad.extend_from_slice(&self.transcript);
        aad.extend_from_slice(RATCHET_DOMAIN);
        aad.extend_from_slice(&header.to_bytes());
        aad
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.recv_count >= until {
            return Ok(());
        }

        let missing = until - self.recv_count;
        if missing > self.max_skip {
            return Err(Error::TooManySkipped);
        }

        let remote = self.remote_dh.ok_or(Error::RatchetState)?;
        let start = self.recv_count;
        let mut chain = self.recv_chain.take().ok_or(Error::RatchetState)?;

        for offset in 0..missing {
            let message_key = chain.next();
            self.skipped.insert((remote, start + offset), message_key);
        }

        self.recv_chain = Some(chain);
        self.recv_count = until;

        if self.skipped.len() > self.max_skip as usize {
            return Err(Error::TooManySkipped);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) -> Result<()> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.remote_dh = Some(header.dh);

        let shared = self
            .self_dh
            .diffie_hellman(&PublicKey::from(header.dh))
            .to_bytes();
        let (root_key, recv_chain) = kdf_root(&self.root_key, &shared);
        self.root_key = root_key;
        self.recv_chain = Some(ChainKey { key: recv_chain });

        let new_dh = StaticSecret::from(random_array::<32>());
        self.self_dh_public = PublicKey::from(&new_dh).to_bytes();
        self.self_dh = new_dh;

        let shared = self
            .self_dh
            .diffie_hellman(&PublicKey::from(header.dh))
            .to_bytes();
        let (root_key, send_chain) = kdf_root(&self.root_key, &shared);
        self.root_key = root_key;
        self.send_chain = Some(ChainKey { key: send_chain });
        Ok(())
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.transcript.zeroize();
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::x3dh::{self, PrekeyPair, initiate, respond};

    fn pair() -> (Ratchet, Ratchet) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (bob_prekeys, bundle) = PrekeyPair::generate(&bob);

        let (initiation, alice_session) = initiate(&alice, &bundle).unwrap();
        let bob_session = respond(&bob, &bob_prekeys, &initiation).unwrap();
        assert_eq!(alice_session, bob_session);

        let transcript = x3dh::transcript(&initiation, &bob.public());
        let alice_ratchet =
            Ratchet::new_initiator(&alice_session, &bundle.signed_prekey, transcript.clone());

        let PrekeyPair { signed_prekey, .. } = bob_prekeys;
        let bob_ratchet = Ratchet::new_responder(&bob_session, signed_prekey, transcript);
        (alice_ratchet, bob_ratchet)
    }

    #[test]
    fn bidirectional_conversation() {
        let (mut alice, mut bob) = pair();

        let (h, ct) = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"hello bob");

        let (h, ct) = bob.encrypt(b"hello alice").unwrap();
        assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"hello alice");

        for i in 0..10u32 {
            let message = format!("message {i}");
            let (h, ct) = alice.encrypt(message.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&h, &ct).unwrap(), message.as_bytes());

            let (h, ct) = bob.encrypt(message.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&h, &ct).unwrap(), message.as_bytes());
        }
    }

    #[test]
    fn out_of_order_delivery_uses_skipped_keys() {
        let (mut alice, mut bob) = pair();

        let (h0, c0) = alice.encrypt(b"zero").unwrap();
        let (h1, c1) = alice.encrypt(b"one").unwrap();
        let (h2, c2) = alice.encrypt(b"two").unwrap();

        assert_eq!(bob.decrypt(&h2, &c2).unwrap(), b"two");
        assert_eq!(bob.decrypt(&h0, &c0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&h1, &c1).unwrap(), b"one");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, mut ct) = alice.encrypt(b"secret").unwrap();
        ct[aead::NONCE_LEN + 3] ^= 1;
        assert!(bob.decrypt(&h, &ct).is_err());
    }

    #[test]
    fn forged_header_does_not_break_session() {
        // C1: a forged frame with chosen headers must not mutate state.
        let (mut alice, mut bob) = pair();

        let (h, ct) = alice.encrypt(b"first").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"first");

        // Forged frame: fresh random dh, plausible pn/n, garbage wire.
        let forged = Header {
            dh: random_array::<32>(),
            pn: 0,
            n: 1,
        };
        assert!(bob.decrypt(&forged, &[0u8; 64]).is_err());

        // The session must still decrypt the next legitimate message.
        let (h, ct) = alice.encrypt(b"second").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"second");
    }

    #[test]
    fn replay_is_rejected_without_desync() {
        // C2: replaying a consumed message fails and the chain stays put.
        let (mut alice, mut bob) = pair();

        let (h, ct) = alice.encrypt(b"once").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"once");
        assert!(matches!(
            bob.decrypt(&h, &ct),
            Err(crate::Error::Replay)
        ));

        let (h, ct) = alice.encrypt(b"twice").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"twice");
    }

    #[test]
    fn forged_skipped_copy_does_not_consume_key() {
        // C2: a tampered copy of a skipped message must not eat the
        // stored skipped key; the real message still decrypts after.
        let (mut alice, mut bob) = pair();

        let (h0, c0) = alice.encrypt(b"zero").unwrap();
        let (h1, c1) = alice.encrypt(b"one").unwrap();
        let (h2, c2) = alice.encrypt(b"two").unwrap();

        // Deliver out of order: #2 first skips #0 and #1.
        assert_eq!(bob.decrypt(&h2, &c2).unwrap(), b"two");

        // Forged copy of #0 (tampered ciphertext) must fail...
        let mut forged = c0.clone();
        forged[aead::NONCE_LEN + 2] ^= 1;
        assert!(bob.decrypt(&h0, &forged).is_err());

        // ...and the original #0 (and #1) must still decrypt.
        assert_eq!(bob.decrypt(&h0, &c0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&h1, &c1).unwrap(), b"one");
    }

    #[test]
    fn header_roundtrip() {
        let header = Header {
            dh: [7u8; 32],
            pn: 42,
            n: 9,
        };
        assert_eq!(Header::from_bytes(&header.to_bytes()).unwrap(), header);
        assert!(Header::from_bytes(&[0u8; 7]).is_err());
    }

    #[test]
    fn snapshot_roundtrip_keeps_conversation_working() {
        let (mut alice, mut bob) = pair();

        let (h, ct) = alice.encrypt(b"before restart").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"before restart");

        // Persist and restore both sides mid-conversation.
        let mut alice = Ratchet::from_snapshot(alice.snapshot()).unwrap();
        let mut bob = Ratchet::from_snapshot(bob.snapshot()).unwrap();

        let (h, ct) = alice.encrypt(b"after restart").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"after restart");

        let (h, ct) = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"reply");
    }

    #[test]
    fn snapshot_rejects_corrupted_ratchet_key() {
        let (alice, _) = pair();
        let mut snapshot = alice.snapshot();
        snapshot.self_dh_public[0] ^= 1;
        assert!(matches!(
            Ratchet::from_snapshot(snapshot),
            Err(Error::InvalidKey)
        ));
    }
}
