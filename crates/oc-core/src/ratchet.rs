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
        self.send_count = self
            .send_count
            .checked_add(1)
            .ok_or(Error::RatchetState)?;

        let aad = self.associated_data(&header);
        let nonce = random_array::<{ aead::NONCE_LEN }>();
        let ciphertext = aead::encrypt(&message_key, &nonce, &aad, plaintext)?;

        let mut wire = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ciphertext);
        Ok((header, wire))
    }

    /// Decrypt one message.
    pub fn decrypt(&mut self, header: &Header, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < aead::NONCE_LEN + aead::TAG_LEN {
            return Err(Error::InvalidLength);
        }

        let nonce: [u8; aead::NONCE_LEN] = wire[..aead::NONCE_LEN]
            .try_into()
            .expect("length checked");
        let ciphertext = &wire[aead::NONCE_LEN..];
        let aad = self.associated_data(header);

        if let Some(message_key) = self.skipped.remove(&(header.dh, header.n)) {
            return aead::decrypt(&message_key, &nonce, &aad, ciphertext);
        }

        if self.remote_dh != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }

        self.skip_message_keys(header.n)?;

        let chain = self.recv_chain.as_mut().ok_or(Error::RatchetState)?;
        let message_key = chain.next();
        self.recv_count = self
            .recv_count
            .checked_add(1)
            .ok_or(Error::RatchetState)?;

        aead::decrypt(&message_key, &nonce, &aad, ciphertext)
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
        let alice_ratchet = Ratchet::new_initiator(
            &alice_session,
            &bundle.signed_prekey,
            transcript.clone(),
        );

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
    fn header_roundtrip() {
        let header = Header {
            dh: [7u8; 32],
            pn: 42,
            n: 9,
        };
        assert_eq!(Header::from_bytes(&header.to_bytes()).unwrap(), header);
        assert!(Header::from_bytes(&[0u8; 7]).is_err());
    }
}
