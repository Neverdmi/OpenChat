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

/// Current UNIX time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
