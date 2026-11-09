//! Hybrid X3DH handshake.
//!
//! Classic X3DH (three X25519 DH operations) mixed with an ML-KEM-768
//! encapsulation. The resulting 32-byte session key seeds both the Double
//! Ratchet and the rotating mailbox chains.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::{Identity, PublicIdentity, SIGNATURE_LEN};
use crate::kdf::hkdf32;
use crate::pq::{self, MLKEM768_SEED_LEN, PqPrekeyPair};
use crate::{Error, PROTOCOL_VERSION, Result, now_unix, random_array};

type Blake2b256 = Blake2b<U32>;

const X3DH_INFO: &[u8] = b"openchat/x3dh/v1";
const BUNDLE_DOMAIN: &[u8] = b"openchat/bundle/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"openchat/transcript/v1";

/// Serialized length of a [`PrekeyPair`]: signed prekey + ML-KEM seed.
pub const PREKEY_PAIR_LEN: usize = 32 + MLKEM768_SEED_LEN;
/// Fixed overhead of a serialized [`PrekeyBundle`] (without the PQ key).
pub const BUNDLE_OVERHEAD: usize = 1 + 32 + 32 + 32 + 8 + 2 + SIGNATURE_LEN;
/// Fixed overhead of a serialized [`Initiation`] (without the PQ ciphertext).
pub const INITIATION_OVERHEAD: usize = 1 + 32 + 32 + 32 + 2;

/// Public prekey bundle distributed inside an invite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyBundle {
    /// Owner's long-term identity.
    pub identity: PublicIdentity,
    /// X25519 signed prekey.
    pub signed_prekey: [u8; 32],
    /// Serialized ML-KEM-768 encapsulation key.
    pub pq_prekey: Vec<u8>,
    /// Creation time, UNIX seconds.
    pub created_at: u64,
    /// Ed25519 signature over all of the above.
    pub signature: [u8; SIGNATURE_LEN],
}

impl PrekeyBundle {
    fn signing_message(&self) -> Vec<u8> {
        bundle_signing_message(
            &self.identity,
            &self.signed_prekey,
            &self.pq_prekey,
            self.created_at,
        )
    }

    /// Verify the owner's signature, plus freshness (audit M-C1):
    /// future-dated bundles and bundles older than the retired-prekey
    /// window are rejected, and the PQ key must be exactly ML-KEM-768.
    pub fn verify(&self) -> Result<()> {
        let now = crate::now_unix();
        if self.created_at > now.saturating_add(300) {
            return Err(Error::InvalidLength);
        }
        if now.saturating_sub(self.created_at) > 14 * 86_400 {
            return Err(Error::InvalidLength);
        }
        if self.pq_prekey.len() != crate::pq::MLKEM768_EK_LEN {
            return Err(Error::InvalidLength);
        }
        self.identity
            .verify(&self.signing_message(), &self.signature)
    }

    /// Stable digest for invite links and TOFU pinning.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(b"openchat/bundle-digest/v1");
        hasher.update(self.signing_message());
        hasher.finalize().into()
    }

    /// Serialize as specified in `SPEC.md` §3.
    ///
    /// `version(1) | Ed25519(32) | X25519(32) | SPK(32) | created_at(8) |
    /// pq_len(2) | PQK | signature(64)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_len = u16::try_from(self.pq_prekey.len()).expect("pq key length fits u16");
        let mut out = Vec::with_capacity(BUNDLE_OVERHEAD + self.pq_prekey.len());
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.identity.ed_bytes());
        out.extend_from_slice(&self.identity.dh_bytes());
        out.extend_from_slice(&self.signed_prekey);
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&pq_len.to_le_bytes());
        out.extend_from_slice(&self.pq_prekey);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a bundle produced by [`PrekeyBundle::to_bytes`].
    ///
    /// The signature is **not** verified here; call [`PrekeyBundle::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BUNDLE_OVERHEAD {
            return Err(Error::InvalidLength);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let ed: [u8; 32] = bytes[1..33].try_into().expect("length checked");
        let dh: [u8; 32] = bytes[33..65].try_into().expect("length checked");
        let signed_prekey: [u8; 32] = bytes[65..97].try_into().expect("length checked");
        let created_at = u64::from_le_bytes(bytes[97..105].try_into().expect("length checked"));
        let pq_len =
            u16::from_le_bytes(bytes[105..107].try_into().expect("length checked")) as usize;

        let pq_end = 107usize.checked_add(pq_len).ok_or(Error::InvalidLength)?;
        if pq_end + SIGNATURE_LEN != bytes.len() {
            return Err(Error::InvalidLength);
        }

        let pq_prekey = bytes[107..pq_end].to_vec();
        let signature: [u8; SIGNATURE_LEN] = bytes[pq_end..].try_into().expect("length checked");

        Ok(Self {
            identity: PublicIdentity::from_bytes(&ed, &dh)?,
            signed_prekey,
            pq_prekey,
            created_at,
            signature,
        })
    }
}

fn bundle_signing_message(
    identity: &PublicIdentity,
    signed_prekey: &[u8; 32],
    pq_prekey: &[u8],
    created_at: u64,
) -> Vec<u8> {
    // SPEC §3: signature covers `BUNDLE_DOMAIN || version || IK_sign ||
    // IK_dh || SPK || created_at(8) || pq_len(2) || PQK` — the exact
    // `to_bytes` layout minus the signature field itself.
    let mut message = Vec::with_capacity(64 + 32 + pq_prekey.len() + 12);
    message.extend_from_slice(BUNDLE_DOMAIN);
    message.push(PROTOCOL_VERSION);
    message.extend_from_slice(&identity.ed_bytes());
    message.extend_from_slice(&identity.dh_bytes());
    message.extend_from_slice(signed_prekey);
    message.extend_from_slice(&created_at.to_le_bytes());
    let pq_len = u16::try_from(pq_prekey.len()).expect("pq key length fits u16");
    message.extend_from_slice(&pq_len.to_le_bytes());
    message.extend_from_slice(pq_prekey);
    message
}

/// Private half of a prekey bundle.
pub struct PrekeyPair {
    /// Signed X25519 prekey.
    pub signed_prekey: StaticSecret,
    /// ML-KEM decapsulation key.
    pub pq: PqPrekeyPair,
}

impl core::fmt::Debug for PrekeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrekeyPair(<redacted>)")
    }
}

impl PrekeyPair {
    /// Generate a new prekey pair and the matching signed bundle.
    pub fn generate(owner: &Identity) -> (Self, PrekeyBundle) {
        let signed_prekey = StaticSecret::from(random_array::<32>());
        let pq = PqPrekeyPair::generate();

        let mut bundle = PrekeyBundle {
            identity: owner.public(),
            signed_prekey: PublicKey::from(&signed_prekey).to_bytes(),
            pq_prekey: pq.public_bytes(),
            created_at: now_unix(),
            signature: [0u8; SIGNATURE_LEN],
        };

        let message = bundle.signing_message();
        bundle.signature = owner.sign(&message);
        (Self { signed_prekey, pq }, bundle)
    }

    /// Serialize the private prekeys as `SPK secret(32) || ML-KEM seed(64)`.
    ///
    /// The returned value is secret material and must only be written to
    /// encrypted storage.
    pub fn to_bytes(&self) -> [u8; PREKEY_PAIR_LEN] {
        let mut out = [0u8; PREKEY_PAIR_LEN];
        out[..32].copy_from_slice(&self.signed_prekey.to_bytes());
        out[32..].copy_from_slice(&self.pq.secret_bytes());
        out
    }

    /// Restore prekeys from [`PrekeyPair::to_bytes`].
    pub fn from_bytes(bytes: &[u8; PREKEY_PAIR_LEN]) -> Self {
        let spk: [u8; 32] = bytes[..32].try_into().expect("length checked");
        let pq_seed: [u8; MLKEM768_SEED_LEN] = bytes[32..].try_into().expect("length checked");
        Self {
            signed_prekey: StaticSecret::from(spk),
            pq: PqPrekeyPair::from_secret_bytes(&pq_seed),
        }
    }

    /// Public half of the signed prekey, used as the handshake mailbox.
    pub fn signed_prekey_public(&self) -> [u8; 32] {
        PublicKey::from(&self.signed_prekey).to_bytes()
    }
}

/// First message of a handshake, sent inside a sealed envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initiation {
    /// Initiator's public identity.
    pub initiator: PublicIdentity,
    /// Ephemeral X25519 public key.
    pub ephemeral: [u8; 32],
    /// ML-KEM-768 ciphertext.
    pub pq_ciphertext: Vec<u8>,
}

impl Initiation {
    /// Serialize as `version(1) | Ed25519(32) | X25519(32) | eph(32) |
    /// pq_len(2) | PQ ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_len = u16::try_from(self.pq_ciphertext.len()).expect("pq ciphertext length fits u16");
        let mut out = Vec::with_capacity(INITIATION_OVERHEAD + self.pq_ciphertext.len());
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(&self.initiator.ed_bytes());
        out.extend_from_slice(&self.initiator.dh_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&pq_len.to_le_bytes());
        out.extend_from_slice(&self.pq_ciphertext);
        out
    }

    /// Parse an initiation produced by [`Initiation::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < INITIATION_OVERHEAD {
            return Err(Error::InvalidLength);
        }
        if bytes[0] != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let ed: [u8; 32] = bytes[1..33].try_into().expect("length checked");
        let dh: [u8; 32] = bytes[33..65].try_into().expect("length checked");
        let ephemeral: [u8; 32] = bytes[65..97].try_into().expect("length checked");
        let pq_len = u16::from_le_bytes(bytes[97..99].try_into().expect("length checked")) as usize;

        if 99usize.checked_add(pq_len).ok_or(Error::InvalidLength)? != bytes.len() {
            return Err(Error::InvalidLength);
        }

        Ok(Self {
            initiator: PublicIdentity::from_bytes(&ed, &dh)?,
            ephemeral,
            pq_ciphertext: bytes[99..].to_vec(),
        })
    }
}

/// Run the initiator side of the handshake.
///
/// Returns the message to send and the 32-byte session key.
pub fn initiate(me: &Identity, bundle: &PrekeyBundle) -> Result<(Initiation, [u8; 32])> {
    bundle.verify()?;

    let my_public = me.public();
    let responder_spk = PublicKey::from(bundle.signed_prekey);
    let ephemeral = StaticSecret::from(random_array::<32>());
    let ephemeral_public = PublicKey::from(&ephemeral);

    let dh1 = crate::dh_shared(me.dh(), &responder_spk)?;
    let dh2 = crate::dh_shared(&ephemeral, &bundle.identity.dh)?;
    let dh3 = crate::dh_shared(&ephemeral, &responder_spk)?;
    let (pq_ciphertext, pq_shared) = pq::encapsulate(&bundle.pq_prekey)?;

    let session_key =
        derive_session_key(&dh1, &dh2, &dh3, &pq_shared, &my_public, &bundle.identity);

    let initiation = Initiation {
        initiator: my_public,
        ephemeral: ephemeral_public.to_bytes(),
        pq_ciphertext,
    };
    Ok((initiation, session_key))
}

/// Run the responder side of the handshake.
pub fn respond(me: &Identity, prekeys: &PrekeyPair, initiation: &Initiation) -> Result<[u8; 32]> {
    let my_public = me.public();
    // Self-handshakes are meaningless and enable reflection attacks.
    if initiation.initiator.peer_id() == my_public.peer_id() {
        return Err(Error::InvalidKey);
    }
    let ephemeral = PublicKey::from(initiation.ephemeral);

    let dh1 = crate::dh_shared(&prekeys.signed_prekey, &initiation.initiator.dh)?;
    let dh2 = crate::dh_shared(me.dh(), &ephemeral)?;
    let dh3 = crate::dh_shared(&prekeys.signed_prekey, &ephemeral)?;
    let pq_shared = prekeys.pq.decapsulate(&initiation.pq_ciphertext)?;

    Ok(derive_session_key(
        &dh1,
        &dh2,
        &dh3,
        &pq_shared,
        &initiation.initiator,
        &my_public,
    ))
}

fn derive_session_key(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    pq_shared: &[u8; 32],
    initiator: &PublicIdentity,
    responder: &PublicIdentity,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(4 * 32);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(pq_shared);

    let mut info = X3DH_INFO.to_vec();
    info.extend_from_slice(&initiator.ed_bytes());
    info.extend_from_slice(&responder.ed_bytes());

    hkdf32(&[0u8; 32], &ikm, &info)
}

/// Canonical handshake transcript, used as associated data by the ratchet.
pub fn transcript(initiation: &Initiation, responder: &PublicIdentity) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 128 + initiation.pq_ciphertext.len());
    out.extend_from_slice(TRANSCRIPT_DOMAIN);
    out.extend_from_slice(&initiation.initiator.ed_bytes());
    out.extend_from_slice(&initiation.initiator.dh_bytes());
    out.extend_from_slice(&responder.ed_bytes());
    out.extend_from_slice(&responder.dh_bytes());
    out.extend_from_slice(&initiation.ephemeral);
    out.extend_from_slice(&(initiation.pq_ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&initiation.pq_ciphertext);
    out
}

/// Root of the mailbox chain family, derived from the session key.
pub fn mailbox_root(session_key: &[u8; 32]) -> [u8; 32] {
    hkdf32(&[], session_key, b"openchat/mailbox-root/v1")
}

/// Root key of the Double Ratchet, derived from the session key.
pub fn ratchet_root(session_key: &[u8; 32]) -> [u8; 32] {
    hkdf32(&[], session_key, b"openchat/ratchet-root/v1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn bundle_signing_layout_is_golden_locked() {
        // Golden vector (audit H4): the signed byte layout must stay
        // exactly `domain || version || IK_sign || IK_dh || SPK ||
        // created_at(8) || pq_len(2) || PQK` per SPEC §3.
        let identity_bytes = [7u8; 64];
        let identity = Identity::from_bytes(&identity_bytes);
        let pq = vec![9u8; 1184];
        let bundle = PrekeyBundle {
            identity: identity.public(),
            signed_prekey: [3u8; 32],
            pq_prekey: pq,
            created_at: 1_700_000_000,
            signature: [0u8; SIGNATURE_LEN],
        };
        let message = bundle.signing_message();
        assert_eq!(
            message.len(),
            BUNDLE_DOMAIN.len() + 1 + 32 + 32 + 32 + 8 + 2 + 1184
        );
        assert!(message.starts_with(BUNDLE_DOMAIN));
        assert_eq!(message[BUNDLE_DOMAIN.len()], PROTOCOL_VERSION);
        // created_at (le) at fixed offset, then pq_len (le), then PQK.
        let created_off = BUNDLE_DOMAIN.len() + 1 + 96;
        assert_eq!(
            &message[created_off..created_off + 8],
            &1_700_000_000u64.to_le_bytes()
        );
        assert_eq!(
            &message[created_off + 8..created_off + 10],
            &1184u16.to_le_bytes()
        );
        assert!(message[created_off + 10..].iter().all(|b| *b == 9));
    }

    fn handshake() -> (
        Identity,
        Identity,
        [u8; 32],
        [u8; 32],
        Initiation,
        PrekeyPair,
    ) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (bob_prekeys, bundle) = PrekeyPair::generate(&bob);

        let (initiation, alice_key) = initiate(&alice, &bundle).unwrap();
        let bob_key = respond(&bob, &bob_prekeys, &initiation).unwrap();

        (alice, bob, alice_key, bob_key, initiation, bob_prekeys)
    }

    #[test]
    fn both_sides_derive_the_same_session_key() {
        let (_alice, _bob, alice_key, bob_key, _, _) = handshake();
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn tampered_bundle_signature_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (_, mut bundle) = PrekeyPair::generate(&bob);
        bundle.signature[0] ^= 1;
        assert!(matches!(
            initiate(&alice, &bundle),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn tampered_pq_ciphertext_breaks_agreement() {
        let (_alice, bob, alice_key, _, mut initiation, bob_prekeys) = handshake();
        initiation.pq_ciphertext[0] ^= 1;
        let bob_key = respond(&bob, &bob_prekeys, &initiation).unwrap();
        assert_ne!(alice_key, bob_key);
    }

    #[test]
    fn transcript_is_stable_and_role_ordered() {
        let (_alice, bob, _, _, initiation, _) = handshake();
        let a = transcript(&initiation, &bob.public());
        let b = transcript(&initiation, &bob.public());
        assert_eq!(a, b);
        assert!(a.starts_with(TRANSCRIPT_DOMAIN));
    }

    #[test]
    fn mailbox_and_ratchet_roots_are_separated() {
        let key = [5u8; 32];
        assert_ne!(mailbox_root(&key), ratchet_root(&key));
        assert_ne!(mailbox_root(&key), key);
    }

    #[test]
    fn bundle_wire_roundtrip() {
        let bob = Identity::generate();
        let (_, bundle) = PrekeyPair::generate(&bob);
        let bytes = bundle.to_bytes();
        let parsed = PrekeyBundle::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, bundle);
        parsed.verify().unwrap();

        let mut tampered = bytes;
        tampered[70] ^= 1;
        let parsed = PrekeyBundle::from_bytes(&tampered).unwrap();
        assert!(parsed.verify().is_err());
    }

    #[test]
    fn prekey_pair_roundtrip_survives_restart() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (prekeys, bundle) = PrekeyPair::generate(&bob);
        let (initiation, alice_key) = initiate(&alice, &bundle).unwrap();

        // Simulate a process restart: serialize and restore the private keys.
        let restored = PrekeyPair::from_bytes(&prekeys.to_bytes());
        assert_eq!(restored.signed_prekey_public(), bundle.signed_prekey);

        let bob_key = respond(&bob, &restored, &initiation).unwrap();
        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn initiation_wire_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (_, bundle) = PrekeyPair::generate(&bob);
        let (initiation, _) = initiate(&alice, &bundle).unwrap();

        let bytes = initiation.to_bytes();
        let parsed = Initiation::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, initiation);
        assert!(Initiation::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn wire_parsers_reject_unknown_versions() {
        assert!(matches!(
            Initiation::from_bytes(&[9u8; INITIATION_OVERHEAD]),
            Err(Error::UnsupportedVersion)
        ));
        assert!(matches!(
            PrekeyBundle::from_bytes(&[9u8; BUNDLE_OVERHEAD]),
            Err(Error::UnsupportedVersion)
        ));
    }
}
