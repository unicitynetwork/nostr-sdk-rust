//! Error type for the crate.

use alloc::string::String;

/// Errors produced by the Nostr protocol/crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A key, nonce, IV, or other byte input had the wrong length.
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),

    /// secp256k1 / schnorr operation failed (bad key, bad point, bad signature).
    #[error("secp256k1 error: {0}")]
    Secp(&'static str),

    /// AEAD (ChaCha20-Poly1305) or AES-CBC decryption failed (bad tag / bad padding).
    #[error("decryption failed: {0}")]
    Decrypt(&'static str),

    /// NIP-44 padding was malformed.
    #[error("invalid nip44 padding: {0}")]
    Padding(&'static str),

    /// Base64/hex decode failure.
    #[error("decode error: {0}")]
    Decode(String),

    /// Wire format did not match what we expected (e.g. NIP-04 `?iv=` framing).
    #[error("malformed payload: {0}")]
    Malformed(&'static str),

    /// GZIP (NIP-04 large-message extension) failure.
    #[error("gzip error: {0}")]
    Gzip(String),

    /// UTF-8 decode failure on a decrypted plaintext.
    #[error("invalid utf-8 in plaintext")]
    Utf8,
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;
