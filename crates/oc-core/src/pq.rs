//! ML-KEM-768 post-quantum prekey helpers.
//!
//! The wire format treats post-quantum keys and ciphertexts as opaque byte
//! strings so that the protocol version can evolve independently of the
//! concrete KEM crate.

use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, KeyExport, MlKem768, TryKeyInit};

use crate::{Error, Result};

/// Serialized ML-KEM-768 encapsulation key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// Serialized ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Serialized ML-KEM-768 decapsulation-key seed length.
pub const MLKEM768_SEED_LEN: usize = 64;

/// A decapsulation (private) key with its encapsulation key.
pub struct PqPrekeyPair {
    dk: DecapsulationKey768,
}

impl core::fmt::Debug for PqPrekeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PqPrekeyPair(<redacted>)")
    }
}

impl PqPrekeyPair {
    /// Generate a fresh ML-KEM-768 keypair.
    pub fn generate() -> Self {
        let (dk, _) = MlKem768::generate_keypair();
        Self { dk }
    }

    /// Serialized encapsulation key for publishing in a [`crate::x3dh::PrekeyBundle`].
    pub fn public_bytes(&self) -> Vec<u8> {
        self.dk.encapsulation_key().to_bytes().as_slice().to_vec()
    }

    /// Serialize the decapsulation key as its 64-byte seed.
    ///
    /// The returned value is secret material and must only be written to
    /// encrypted storage.
    pub fn secret_bytes(&self) -> [u8; MLKEM768_SEED_LEN] {
        let seed = self.dk.to_seed().expect("key was generated from a seed");
        let mut out = [0u8; MLKEM768_SEED_LEN];
        out.copy_from_slice(seed.as_slice());
        out
    }

    /// Restore a decapsulation key from [`PqPrekeyPair::secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8; MLKEM768_SEED_LEN]) -> Self {
        let seed = (*bytes).into();
        Self {
            dk: DecapsulationKey768::from_seed(seed),
        }
    }

    /// Decapsulate a shared secret from a peer.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let shared = self
            .dk
            .decapsulate_slice(ciphertext)
            .map_err(|_| Error::InvalidLength)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }
}

/// Encapsulate a fresh shared secret to a serialized ML-KEM-768 key.
///
/// Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let key =
        EncapsulationKey768::new_from_slice(encapsulation_key).map_err(|_| Error::InvalidLength)?;
    let (ciphertext, shared) = key.encapsulate();

    let mut secret = [0u8; 32];
    secret.copy_from_slice(shared.as_slice());
    Ok((ciphertext.as_slice().to_vec(), secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_agree() {
        let pair = PqPrekeyPair::generate();
        let ek = pair.public_bytes();
        assert_eq!(ek.len(), MLKEM768_EK_LEN);

        let (ct, sender) = encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);

        let receiver = pair.decapsulate(&ct).unwrap();
        assert_eq!(sender, receiver);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(encapsulate(&[0u8; 3]).is_err());
        let pair = PqPrekeyPair::generate();
        assert!(pair.decapsulate(&[0u8; 3]).is_err());
    }

    #[test]
    fn secret_seed_roundtrip() {
        let pair = PqPrekeyPair::generate();
        let restored = PqPrekeyPair::from_secret_bytes(&pair.secret_bytes());
        assert_eq!(pair.public_bytes(), restored.public_bytes());

        let ek = restored.public_bytes();
        let (ct, sender) = encapsulate(&ek).unwrap();
        assert_eq!(pair.decapsulate(&ct).unwrap(), sender);
    }
}
