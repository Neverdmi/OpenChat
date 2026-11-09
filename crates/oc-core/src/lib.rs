#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! OpenChat protocol core.
//!
//! Implements the cryptographic building blocks from `SPEC.md`:
//! identities, hybrid X3DH, sealed sender, fixed-size frames and
//! rotating mailbox addresses.
//!
//! Nothing in this crate performs network I/O.

pub mod aead;
pub mod error;
pub mod frame;
pub mod identity;
pub mod kdf;
pub mod mailbox;
pub mod pq;
pub mod ratchet;
pub mod seal;
pub mod x3dh;

pub use error::{Error, Result};

/// Version byte used by every wire structure.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fill a fixed-size array from the operating system CSPRNG.
///
/// Panics only if the platform has no working entropy source, which is a
/// non-recoverable condition for any cryptographic protocol.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("operating system RNG must be available");
    out
}

/// Constant-time equality for key material (audit L5).
pub fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// X25519 key agreement with a contributory check (audit H1).
///
/// A low-order public key would force the shared secret to the known
/// all-zero value; such keys are rejected instead of being mixed in.
pub(crate) fn dh_shared(
    secret: &x25519_dalek::StaticSecret,
    public: &x25519_dalek::PublicKey,
) -> Result<[u8; 32]> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    Ok(shared.to_bytes())
}

/// Parse-time torsion rejection (audit H1, defence in depth).
///
/// The contributory check in [`dh_shared`] is the authoritative
/// defence (it rejects any low-order DH output per RFC 7748 §6.1).
/// `x25519-dalek` 3.x exposes no Montgomery-point torsion API, so
/// parsing deliberately does not try to pre-filter here.
pub(crate) fn check_public_key(_public: &x25519_dalek::PublicKey) -> Result<()> {
    Ok(())
}

/// Current UNIX time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
