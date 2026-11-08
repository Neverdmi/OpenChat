//! Long-term identities and self-certifying peer identifiers.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, Result, random_array};

type Blake2b256 = Blake2b<U32>;

/// Length of an Ed25519/X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// A private identity: Ed25519 signing key plus X25519 key-agreement key.
pub struct Identity {
    signing: SigningKey,
    dh: StaticSecret,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}

impl Identity {
    /// Generate a fresh identity from the operating system CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::from_bytes(&random_array::<32>()),
            dh: StaticSecret::from(random_array::<32>()),
        }
    }

    /// Public half of this identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            ed: self.signing.verifying_key(),
            dh: PublicKey::from(&self.dh),
        }
    }

    /// Sign a message with the long-term Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Long-term X25519 secret used for X3DH.
    pub fn dh(&self) -> &StaticSecret {
        &self.dh
    }

    /// Self-certifying identifier of this identity.
    pub fn peer_id(&self) -> [u8; 32] {
        self.public().peer_id()
    }

    /// Serialize the private identity as `Ed25519 seed(32) || X25519 secret(32)`.
    ///
    /// The returned value is secret material and must only be written to
    /// encrypted storage.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.dh.to_bytes());
        out
    }

    /// Restore an identity from [`Identity::to_bytes`].
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let signing_bytes: [u8; 32] = bytes[..32].try_into().expect("length checked");
        let dh_bytes: [u8; 32] = bytes[32..].try_into().expect("length checked");
        Self {
            signing: SigningKey::from_bytes(&signing_bytes),
            dh: StaticSecret::from(dh_bytes),
        }
    }
}

/// Public half of an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// Ed25519 verification key.
    pub ed: VerifyingKey,
    /// X25519 key-agreement key.
    pub dh: PublicKey,
}

impl PublicIdentity {
    /// Build from raw bytes, validating the Ed25519 key.
    pub fn from_bytes(ed: &[u8; PUBLIC_KEY_LEN], dh: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        Ok(Self {
            ed: VerifyingKey::from_bytes(ed).map_err(|_| Error::InvalidKey)?,
            dh: PublicKey::from(*dh),
        })
    }

    /// Raw Ed25519 bytes.
    pub fn ed_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.ed.to_bytes()
    }

    /// Raw X25519 bytes.
    pub fn dh_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.dh.to_bytes()
    }

    /// Self-certifying identifier: `BLAKE2b-256(domain || Ed25519 public key)`.
    pub fn peer_id(&self) -> [u8; 32] {
        let mut hasher = Blake2b256::new();
        hasher.update(b"openchat/peer-id/v1");
        hasher.update(self.ed.as_bytes());
        hasher.finalize().into()
    }

    /// Verify an Ed25519 signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        self.ed
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| Error::BadSignature)
    }
}

/// Verify a detached Ed25519 signature with a raw public key.
///
/// Used for signed relay manifests, where there is a single signing key and
/// no X25519 identity half.
pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidKey)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::BadSignature)
}

/// Safety number for out-of-band key verification.
///
/// Independent of argument order: both sides compute the same value.
pub fn safety_number(a: &PublicIdentity, b: &PublicIdentity) -> [u8; 32] {
    let (first, second) = if a.ed_bytes() <= b.ed_bytes() {
        (a, b)
    } else {
        (b, a)
    };

    let mut hasher = Blake2b256::new();
    hasher.update(b"openchat/safety/v1");
    hasher.update(first.ed_bytes());
    hasher.update(second.ed_bytes());
    hasher.update(first.dh_bytes());
    hasher.update(second.dh_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_and_signature() {
        let id = Identity::generate();
        let public = id.public();
        let parsed = PublicIdentity::from_bytes(&public.ed_bytes(), &public.dh_bytes()).unwrap();
        assert_eq!(parsed.peer_id(), id.peer_id());

        let sig = id.sign(b"message");
        parsed.verify(b"message", &sig).unwrap();
        assert!(parsed.verify(b"other", &sig).is_err());
    }

    #[test]
    fn safety_number_is_order_independent() {
        let a = Identity::generate().public();
        let b = Identity::generate().public();
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    #[test]
    fn peer_id_is_deterministic() {
        let id = Identity::generate();
        assert_eq!(id.peer_id(), id.public().peer_id());
        assert_ne!(id.peer_id(), Identity::generate().peer_id());
    }

    #[test]
    fn private_identity_roundtrip() {
        let id = Identity::generate();
        let restored = Identity::from_bytes(&id.to_bytes());
        assert_eq!(restored.peer_id(), id.peer_id());
        assert_eq!(restored.public(), id.public());

        let signature = restored.sign(b"persisted");
        id.public().verify(b"persisted", &signature).unwrap();
    }
}
