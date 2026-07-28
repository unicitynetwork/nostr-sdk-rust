//! The `Signer` seam — the custody boundary.
//!
//! Protocol code (event signing, NIP-04/44 encryption) depends only on this
//! trait, never on a raw private key. In the AOS design the messaging capsule
//! holds a `RemoteSigner` that proxies these calls over the bus to the wallet
//! capsule, so the seed never enters the network-facing capsule. Here we ship
//! [`LocalSigner`] for tests and single-process use.

use crate::crypto::{nip04, nip44, schnorr};
use crate::error::Result;
use crate::keys::Keypair;

/// A custody-agnostic signer. The three secret-dependent operations the Nostr
/// protocol needs are: sign an event id, and derive the NIP-44 conversation key
/// / NIP-04 shared secret for a peer. None expose the private key itself.
pub trait Signer {
    /// The signer's 32-byte x-only public key.
    fn public_key(&self) -> [u8; 32];

    /// BIP-340 sign a 32-byte event id.
    fn schnorr_sign(&self, hash: &[u8; 32]) -> Result<[u8; 64]>;

    /// Derive the 32-byte NIP-44 conversation key for `peer_xonly`.
    fn nip44_conversation_key(&self, peer_xonly: &[u8; 32]) -> Result<[u8; 32]>;

    /// Derive the 32-byte NIP-04 shared secret for `peer_xonly`.
    fn nip04_shared_secret(&self, peer_xonly: &[u8; 32]) -> Result<[u8; 32]>;
}

/// A [`Signer`] that holds the key locally.
#[derive(Clone)]
pub struct LocalSigner {
    keypair: Keypair,
}

impl LocalSigner {
    /// Wrap an existing keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Build directly from a 32-byte secret.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        Ok(Self::new(Keypair::from_secret(secret)?))
    }

    /// The underlying keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

impl Signer for LocalSigner {
    fn public_key(&self) -> [u8; 32] {
        *self.keypair.public_key()
    }

    fn schnorr_sign(&self, hash: &[u8; 32]) -> Result<[u8; 64]> {
        schnorr::sign(hash, self.keypair.secret_bytes())
    }

    fn nip44_conversation_key(&self, peer_xonly: &[u8; 32]) -> Result<[u8; 32]> {
        nip44::derive_conversation_key(self.keypair.secret_bytes(), peer_xonly)
    }

    fn nip04_shared_secret(&self, peer_xonly: &[u8; 32]) -> Result<[u8; 32]> {
        nip04::derive_shared_secret(self.keypair.secret_bytes(), peer_xonly)
    }
}
