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
use crate::pq::{self, PqPrekeyPair};
use crate::{Result, now_unix, random_array};

type Blake2b256 = Blake2b<U32>;

const X3DH_INFO: &[u8] = b"openchat/x3dh/v1";
const BUNDLE_DOMAIN: &[u8] = b"openchat/bundle/v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"openchat/transcript/v1";

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

    /// Verify the owner's signature.
    pub fn verify(&self) -> Result<()> {
        self.identity.verify(&self.signing_message(), &self.signature)
    }

    /// Stable digest for invite links and TOFU pinning.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(b"openchat/bundle-digest/v1");
        hasher.update(self.signing_message());
        hasher.finalize().into()
    }
}

fn bundle_signing_message(
    identity: &PublicIdentity,
    signed_prekey: &[u8; 32],
    pq_prekey: &[u8],
    created_at: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(64 + 32 + pq_prekey.len() + 12);
    message.extend_from_slice(BUNDLE_DOMAIN);
    message.extend_from_slice(&identity.ed_bytes());
    message.extend_from_slice(&identity.dh_bytes());
    message.extend_from_slice(signed_prekey);
    message.extend_from_slice(&(pq_prekey.len() as u32).to_le_bytes());
    message.extend_from_slice(pq_prekey);
    message.extend_from_slice(&created_at.to_le_bytes());
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

/// Run the initiator side of the handshake.
///
/// Returns the message to send and the 32-byte session key.
pub fn initiate(me: &Identity, bundle: &PrekeyBundle) -> Result<(Initiation, [u8; 32])> {
    bundle.verify()?;

    let my_public = me.public();
    let responder_spk = PublicKey::from(bundle.signed_prekey);
    let ephemeral = StaticSecret::from(random_array::<32>());
    let ephemeral_public = PublicKey::from(&ephemeral);

    let dh1 = me.dh().diffie_hellman(&responder_spk).to_bytes();
    let dh2 = ephemeral
        .diffie_hellman(&bundle.identity.dh)
        .to_bytes();
    let dh3 = ephemeral.diffie_hellman(&responder_spk).to_bytes();
    let (pq_ciphertext, pq_shared) = pq::encapsulate(&bundle.pq_prekey)?;

    let session_key = derive_session_key(
        &dh1,
        &dh2,
        &dh3,
        &pq_shared,
        &my_public,
        &bundle.identity,
    );

    let initiation = Initiation {
        initiator: my_public,
        ephemeral: ephemeral_public.to_bytes(),
        pq_ciphertext,
    };
    Ok((initiation, session_key))
}

/// Run the responder side of the handshake.
pub fn respond(
    me: &Identity,
    prekeys: &PrekeyPair,
    initiation: &Initiation,
) -> Result<[u8; 32]> {
    let my_public = me.public();
    let ephemeral = PublicKey::from(initiation.ephemeral);

    let dh1 = prekeys
        .signed_prekey
        .diffie_hellman(&initiation.initiator.dh)
        .to_bytes();
    let dh2 = me.dh().diffie_hellman(&ephemeral).to_bytes();
    let dh3 = prekeys.signed_prekey.diffie_hellman(&ephemeral).to_bytes();
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
    let mut out = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 128 + initiation.pq_ciphertext.len());
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

    fn handshake() -> (Identity, Identity, [u8; 32], [u8; 32], Initiation, PrekeyPair) {
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
}
