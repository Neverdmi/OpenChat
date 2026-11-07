//! Rotating mailbox addresses.
//!
//! A relay only ever sees one-shot X25519 public keys. Both sides derive the
//! same sequence from the session's mailbox root, so the sender can address
//! the receiver without any directory lookup.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::kdf::hkdf32;

/// Number of one-shot addresses per UTC day.
pub const SLOTS_PER_EPOCH: u32 = 32;
/// Length of a mailbox epoch in seconds (one day).
pub const EPOCH_SECONDS: u64 = 86_400;

/// Derivation chain for one direction of a conversation.
#[derive(Clone)]
pub struct MailboxChain {
    seed: [u8; 32],
}

impl core::fmt::Debug for MailboxChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MailboxChain(<redacted>)")
    }
}

impl MailboxChain {
    /// Derive the chain for `owner`'s inbox, as addressed by `peer`.
    ///
    /// Both participants compute the same chain: the sender uses
    /// `owner = receiver`, and the receiver uses `owner = self`.
    pub fn derive(root: &[u8; 32], owner: &[u8; 32], peer: &[u8; 32]) -> Self {
        let mut info = b"openchat/inbox/v1".to_vec();
        info.extend_from_slice(owner);
        info.extend_from_slice(peer);
        Self {
            seed: hkdf32(&[], root, &info),
        }
    }

    /// Secret scalar for a slot. Only the inbox owner needs this.
    pub fn slot_secret(&self, epoch: u32, index: u32) -> [u8; 32] {
        let mut info = b"openchat/slot/v1".to_vec();
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(&index.to_le_bytes());
        hkdf32(&[], &self.seed, &info)
    }

    /// Public address of a slot.
    pub fn slot_public(&self, epoch: u32, index: u32) -> [u8; 32] {
        let secret = StaticSecret::from(self.slot_secret(epoch, index));
        PublicKey::from(&secret).to_bytes()
    }

    /// All addresses of an epoch, used to build relay subscriptions.
    pub fn epoch_addresses(&self, epoch: u32) -> Vec<[u8; 32]> {
        (0..SLOTS_PER_EPOCH)
            .map(|index| self.slot_public(epoch, index))
            .collect()
    }
}

/// Epoch number for a UNIX timestamp.
pub fn epoch_of(unix_seconds: u64) -> u32 {
    (unix_seconds / EPOCH_SECONDS) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_and_receiver_derive_the_same_address() {
        let root = [7u8; 32];
        let alice = [1u8; 32];
        let bob = [2u8; 32];

        // Both sides derive Bob's inbox chain: Alice addresses it, Bob reads it.
        let alice_view = MailboxChain::derive(&root, &bob, &alice);
        let bob_view = MailboxChain::derive(&root, &bob, &alice);
        assert_eq!(alice_view.slot_public(10, 3), bob_view.slot_public(10, 3));

        // The public address is the X25519 public key of the slot secret.
        let secret = bob_view.slot_secret(10, 3);
        let expected = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        assert_eq!(bob_view.slot_public(10, 3), expected.to_bytes());

        // Direction separation: Alice's own inbox is a different chain.
        let alice_inbox = MailboxChain::derive(&root, &alice, &bob);
        assert_ne!(alice_inbox.slot_public(10, 3), bob_view.slot_public(10, 3));
    }

    #[test]
    fn addresses_rotate_every_epoch_and_index() {
        let chain = MailboxChain::derive(&[9u8; 32], &[3u8; 32], &[4u8; 32]);
        let a = chain.slot_public(1, 0);
        let b = chain.slot_public(2, 0);
        let c = chain.slot_public(1, 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        assert_eq!(chain.epoch_addresses(1).len(), SLOTS_PER_EPOCH as usize);
    }
}
