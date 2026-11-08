//! Fixed-size frame padding.
//!
//! Every frame is padded to one of a few buckets so that an observer cannot
//! learn the message length from its ciphertext length.

use crate::{Error, Result};

/// Allowed padded frame sizes in bytes.
pub const BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];

/// Smallest bucket that fits `payload_len + 2` bytes.
pub fn bucket_for(payload_len: usize) -> Option<usize> {
    BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= payload_len + 2)
}

/// Pad `payload` to a bucket.
///
/// Layout: `len_le(2) || payload || random_padding`. Padding bytes are inside
/// the AEAD and never visible on the wire.
pub fn pad(payload: &[u8]) -> Result<Vec<u8>> {
    let bucket = bucket_for(payload.len()).ok_or(Error::Frame)?;
    let len = u16::try_from(payload.len()).map_err(|_| Error::Frame)?;

    let mut frame = vec![0u8; bucket];
    frame[..2].copy_from_slice(&len.to_le_bytes());
    frame[2..2 + payload.len()].copy_from_slice(payload);
    getrandom::fill(&mut frame[2 + payload.len()..]).map_err(|_| Error::Rng)?;
    Ok(frame)
}

/// Strip padding and return the original payload.
pub fn unpad(frame: &[u8]) -> Result<&[u8]> {
    if !BUCKETS.contains(&frame.len()) {
        return Err(Error::Frame);
    }

    let len =
        u16::from_le_bytes(frame[..2].try_into().expect("frame has at least 2 bytes")) as usize;
    if len + 2 > frame.len() {
        return Err(Error::Frame);
    }
    Ok(&frame[2..2 + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_expected_buckets() {
        assert_eq!(bucket_for(0), Some(256));
        assert_eq!(bucket_for(254), Some(256));
        assert_eq!(bucket_for(255), Some(1024));
        assert_eq!(bucket_for(16_382), Some(16_384));
        assert_eq!(bucket_for(16_383), None);
    }

    #[test]
    fn roundtrip_every_bucket() {
        for len in [0, 1, 100, 254, 1022, 4094, 16_382] {
            let payload = vec![0xABu8; len];
            let framed = pad(&payload).unwrap();
            assert!(BUCKETS.contains(&framed.len()));
            assert_eq!(unpad(&framed).unwrap(), payload.as_slice());
        }
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(unpad(&[0u8; 10]).is_err());

        let mut frame = pad(b"x").unwrap();
        frame[0] = 0xFF;
        frame[1] = 0xFF;
        assert!(unpad(&frame).is_err());
    }
}
