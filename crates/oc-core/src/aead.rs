//! XChaCha20-Poly1305 AEAD wrapper.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{Error, Result};

/// AEAD key length in bytes.
pub const KEY_LEN: usize = 32;
/// XChaCha20 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypt and authenticate `plaintext` with `aad`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)
}

/// Verify and decrypt `ciphertext` with `aad`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_array;

    #[test]
    fn roundtrip() {
        let key = random_array::<KEY_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let ct = encrypt(&key, &nonce, b"aad", b"hello").unwrap();
        assert_eq!(decrypt(&key, &nonce, b"aad", &ct).unwrap(), b"hello");
    }

    #[test]
    fn tamper_and_wrong_aad_fail() {
        let key = random_array::<KEY_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let mut ct = encrypt(&key, &nonce, b"aad", b"hello").unwrap();
        ct[0] ^= 1;
        assert!(decrypt(&key, &nonce, b"aad", &ct).is_err());
        assert!(decrypt(&key, &nonce, b"other", &ct).is_err());
    }
}
