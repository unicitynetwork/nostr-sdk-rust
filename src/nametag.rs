//! UNIP-01 nametag utilities — a port of `nostr-js-sdk/src/nametag/NametagUtils.ts`.
//!
//! Nametags are addressed privately: the relay-indexed tags are salted SHA-256
//! hashes, never the plaintext. This module covers the deterministic pieces:
//! normalization, hashing, validation, the recoverable AES-256-GCM `encrypted_nametag`,
//! and the UNIP-01 ownership marker used on kind-30078 binding events.
//!
//! Phone-number (E.164) normalization from the reference SDK is **not yet ported**
//! (it needs libphonenumber); [`normalize_nametag`] applies the standard path, which
//! is correct for agent nametags matching `[a-z0-9_-]{3,20}`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::event::Event;

const NAMETAG_SALT: &str = "unicity:nametag:";
const ADDRESS_SALT: &str = "unicity:address:";

/// Minimum nametag length after normalization.
pub const NAMETAG_MIN_LENGTH: usize = 3;
/// Maximum nametag length after normalization.
pub const NAMETAG_MAX_LENGTH: usize = 20;

/// UNIP-01 single-owner marker label (used as `["L", NAMETAG_MARKER_LABEL]`).
pub const NAMETAG_MARKER_LABEL: &str = "unicity:nametag";

/// Hex SHA-256 of a UTF-8 string.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Normalize a nametag: trim, lowercase, strip a trailing `@unicity`.
/// (Phone/E.164 normalization is not yet supported — see module docs.)
pub fn normalize_nametag(nametag: &str) -> String {
    let trimmed = nametag.trim();
    let lower = trimmed.to_lowercase();
    match lower.strip_suffix("@unicity") {
        Some(stripped) => stripped.to_string(),
        None => lower,
    }
}

/// Salted, normalized nametag hash (hex) — the relay-indexed `d`/`t` tag value.
pub fn hash_nametag(nametag: &str) -> String {
    sha256_hex(&alloc::format!(
        "{NAMETAG_SALT}{}",
        normalize_nametag(nametag)
    ))
}

/// Salted address hash (hex) for reverse lookup (address → binding).
pub fn hash_address_for_tag(address: &str) -> String {
    sha256_hex(&alloc::format!("{ADDRESS_SALT}{address}"))
}

/// Validate a nametag: strip a leading `@`, normalize, then require
/// `[a-z0-9_-]{3,20}`. (Phone nametags are not accepted here yet.)
pub fn is_valid_nametag(nametag: &str) -> bool {
    let stripped = nametag.strip_prefix('@').unwrap_or(nametag);
    let n = normalize_nametag(stripped);
    let len = n.chars().count();
    (NAMETAG_MIN_LENGTH..=NAMETAG_MAX_LENGTH).contains(&len)
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Does an event carry the UNIP-01 ownership marker `["L", "unicity:nametag"]`?
pub fn has_ownership_marker(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == "L" && t[1] == NAMETAG_MARKER_LABEL)
}

/// Derive the AES-256 key for `encrypted_nametag`:
/// `HKDF-SHA256(ikm = privkey, salt = SHA-256("sphere-nametag-salt"), info = "nametag-encryption", 32)`.
pub fn derive_nametag_encryption_key(private_key: &[u8; 32]) -> [u8; 32] {
    let salt = Sha256::digest(b"sphere-nametag-salt");
    let hk = Hkdf::<Sha256>::new(Some(&salt), private_key);
    let mut okm = [0u8; 32];
    hk.expand(b"nametag-encryption", &mut okm)
        .expect("hkdf 32 bytes");
    okm
}

/// Encrypt a nametag (AES-256-GCM) with a caller-supplied 12-byte IV.
/// Output = `base64(iv || ciphertext‖tag)`. Byte-identical to the reference SDK
/// for the same IV.
pub fn encrypt_nametag_with_iv(
    nametag: &str,
    private_key: &[u8; 32],
    iv: &[u8; 12],
) -> Result<String> {
    let key = derive_nametag_encryption_key(private_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(iv), nametag.as_bytes())
        .map_err(|_| Error::Decrypt("aes-gcm encrypt"))?;
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(iv);
    combined.extend_from_slice(&ct);
    Ok(STANDARD.encode(combined))
}

/// Decrypt an `encrypted_nametag` produced by [`encrypt_nametag_with_iv`] (or the
/// reference SDK).
pub fn decrypt_nametag(encrypted_b64: &str, private_key: &[u8; 32]) -> Result<String> {
    let combined = STANDARD
        .decode(encrypted_b64)
        .map_err(|e| Error::Decode(alloc::format!("base64: {e}")))?;
    if combined.len() < 12 + 16 {
        return Err(Error::Malformed("encrypted_nametag too short"));
    }
    let (iv, ct) = combined.split_at(12);
    let key = derive_nametag_encryption_key(private_key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(iv), ct)
        .map_err(|_| Error::Decrypt("aes-gcm: bad tag"))?;
    String::from_utf8(pt).map_err(|_| Error::Utf8)
}
