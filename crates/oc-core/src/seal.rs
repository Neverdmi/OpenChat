//! Sealed sender.
//!
//! The outer envelope is encrypted to a one-shot mailbox key and carries no
//! signature, so a relay cannot tell who sent the message. Authenticity is
//! provided by the inner ratchet AEAD.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, PROTOCOL_VERSION, Result, aead, kdf::hkdf32, random_array};

const SEAL_DOMAIN: &[u8] = b"openchat/seal/v1";
/// Overhead of the sealed envelope: version + ephemeral key + nonce + tag.
pub const SEAL_OVERHEAD: usize = 1 + 32 + aead::NONCE_LEN + aead::TAG_LEN;

/// Encrypt `plaintext` to a mailbox public key.
///
/// Wire format: `version(1) || ephemeral_pk(32) || nonce(24) || ciphertext`.
pub fn seal(mailbox_pk: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = StaticSecret::from(random_array::<32>());
    let ephemeral_pk = PublicKey::from(&ephemeral);
    let shared = crate::dh_shared(&ephemeral, &PublicKey::from(*mailbox_pk))?;

    let mut aad = SEAL_DOMAIN.to_vec();
    aad.extend_from_slice(&ephemeral_pk.to_bytes());
    aad.extend_from_slice(mailbox_pk);

    let key = hkdf32(&[], &shared, &aad);
    let nonce = random_array::<{ aead::NONCE_LEN }>();
    let ciphertext = aead::encrypt(&key, &nonce, &aad, plaintext)?;

    let mut wire = Vec::with_capacity(SEAL_OVERHEAD + ciphertext.len());
    wire.push(PROTOCOL_VERSION);
    wire.extend_from_slice(&ephemeral_pk.to_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

/// Decrypt a sealed envelope with the mailbox secret key.
pub fn open(mailbox_sk: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < SEAL_OVERHEAD {
        return Err(Error::InvalidLength);
    }
    if wire[0] != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion);
    }

    let ephemeral_pk: [u8; 32] = wire[1..33].try_into().expect("slice length checked");
    let nonce: [u8; aead::NONCE_LEN] = wire[33..57].try_into().expect("slice length checked");
    let ciphertext = &wire[57..];

    let ephemeral_public = PublicKey::from(ephemeral_pk);
    crate::check_public_key(&ephemeral_public)?;
    let mailbox_secret = StaticSecret::from(*mailbox_sk);
    let shared = crate::dh_shared(&mailbox_secret, &ephemeral_public)?;

    let mut aad = SEAL_DOMAIN.to_vec();
    aad.extend_from_slice(&ephemeral_pk);
    aad.extend_from_slice(&PublicKey::from(&mailbox_secret).to_bytes());

    let key = hkdf32(&[], &shared, &aad);
    aead::decrypt(&key, &nonce, &aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = random_array::<32>();
        let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        (secret, public)
    }

    #[test]
    fn roundtrip() {
        let (secret, public) = mailbox_keypair();
        let wire = seal(&public, b"top secret").unwrap();
        assert_eq!(open(&secret, &wire).unwrap(), b"top secret");
    }

    #[test]
    fn wrong_key_and_tampering_fail() {
        let (secret, public) = mailbox_keypair();
        let (other_secret, _) = mailbox_keypair();
        let mut wire = seal(&public, b"payload").unwrap();

        assert!(open(&other_secret, &wire).is_err());

        wire[40] ^= 1;
        assert!(open(&secret, &wire).is_err());
    }

    #[test]
    fn rejects_short_and_unknown_versions() {
        let (secret, _) = mailbox_keypair();
        assert!(open(&secret, &[0u8; 3]).is_err());

        let (_, public) = mailbox_keypair();
        let mut wire = seal(&public, b"x").unwrap();
        wire[0] = 99;
        assert!(matches!(
            open(&secret, &wire),
            Err(Error::UnsupportedVersion)
        ));
    }
}
