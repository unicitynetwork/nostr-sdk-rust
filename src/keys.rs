//! Nostr key material. A [`Keypair`] holds a 32-byte secret and its x-only
//! (BIP-340) public key. This is the local, in-memory holder; a key-holding /
//! network-facing split is expressed through the [`crate::signer::Signer`] trait.

use alloc::string::String;

use crate::crypto::{bech32, schnorr};
use crate::error::{Error, Result};

/// A secp256k1 keypair with its x-only public key precomputed.
#[derive(Clone)]
pub struct Keypair {
    secret: [u8; 32],
    xonly: [u8; 32],
}

impl Keypair {
    /// Build from a 32-byte secret key.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        let xonly = schnorr::public_key(&secret)?;
        Ok(Self { secret, xonly })
    }

    /// Build from a hex-encoded 32-byte secret key.
    pub fn from_secret_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| Error::Decode(alloc::format!("hex: {e}")))?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidLength("secret != 32"))?;
        Self::from_secret(secret)
    }

    /// Build from an `nsec` bech32 string (NIP-19).
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        Self::from_secret(bech32::decode_nsec(nsec)?)
    }

    /// The 32-byte secret key.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The 32-byte x-only public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.xonly
    }

    /// Hex-encoded x-only public key (lowercase).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.xonly)
    }

    /// Hex-encoded secret key (lowercase).
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    /// `npub` (NIP-19) encoding of the public key.
    pub fn npub(&self) -> Result<String> {
        bech32::encode_npub(&self.xonly)
    }

    /// `nsec` (NIP-19) encoding of the secret key.
    pub fn nsec(&self) -> Result<String> {
        bech32::encode_nsec(&self.secret)
    }
}
