//! Error type shared by the protocol core.

use thiserror::Error;

/// Result alias for the protocol core.
pub type Result<T> = core::result::Result<T, Error>;

/// Protocol core error.
#[derive(Debug, Error)]
pub enum Error {
    /// A key, signature or placeholder had an invalid length.
    #[error("invalid key or length")]
    InvalidLength,

    /// A public key failed validation.
    #[error("invalid public key")]
    InvalidKey,

    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// AEAD encryption failed.
    #[error("encryption failed")]
    Encrypt,

    /// AEAD decryption or authentication failed.
    #[error("decryption failed")]
    Decrypt,

    /// Frame padding or length prefix is malformed.
    #[error("invalid frame")]
    Frame,

    /// Unsupported protocol or structure version.
    #[error("unsupported version")]
    UnsupportedVersion,

    /// HKDF could not produce the requested output length.
    #[error("key derivation failed")]
    Kdf,

    /// Operating system RNG failed.
    #[error("randomness source failed")]
    Rng,

    /// The ratchet was used in an invalid state.
    #[error("ratchet is not ready")]
    RatchetState,

    /// Too many message keys were skipped.
    #[error("too many skipped messages")]
    TooManySkipped,

    /// A message was replayed after it had already been consumed.
    #[error("replayed message")]
    Replay,
}
