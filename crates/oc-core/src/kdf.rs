//! HKDF-SHA256 helpers.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, Result};

fn expand(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| Error::Kdf)
}

/// Derive exactly 32 bytes with HKDF-SHA256.
pub fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    expand(salt, ikm, info, &mut out).expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Derive exactly 64 bytes with HKDF-SHA256.
pub fn hkdf64(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    expand(salt, ikm, info, &mut out).expect("64 bytes is a valid HKDF-SHA256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_separated_by_info() {
        let a = hkdf32(b"salt", b"ikm", b"one");
        let b = hkdf32(b"salt", b"ikm", b"one");
        let c = hkdf32(b"salt", b"ikm", b"two");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
