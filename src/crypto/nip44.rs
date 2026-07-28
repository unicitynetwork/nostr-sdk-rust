//! NIP-44 — the **Unicity/TS variant**, a direct port of
//! `nostr-js-sdk/src/crypto/nip44.ts`. This is NOT official NIP-44 v2:
//!
//! * conversation key = `HKDF-SHA256(ikm = ECDH_x, salt = sorted x-only pubkeys(64B), info = "nip44-v2", 32B)`
//! * per-message key   = `HKDF-SHA256(ikm = conversation_key, salt = nonce(24B), info = "", 76B)`
//!   → `chacha_key = mk[0..32]`, `chacha_nonce = mk[32..44]` (12B); `mk[44..76]` is **unused**
//! * cipher = **ChaCha20-Poly1305 AEAD** (RFC 8439, no AAD); the 16-byte Poly1305 tag is appended
//! * payload = `0x02 || nonce(24) || ciphertext‖tag`, base64 (standard, padded)
//!
//! Do not substitute a generic `nip44` crate — it implements the incompatible
//! official v2 scheme. See github.com/unicitynetwork/nostr-sdk/issues/7 for the
//! separate Java-vs-TS incompatibility.

use alloc::vec::Vec;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::secp;
use crate::error::{Error, Result};

const VERSION: u8 = 0x02;
const NONCE_SIZE: usize = 24;
const MAC_SIZE: usize = 16;
const MIN_PADDED_LEN: usize = 32;
const MAX_MESSAGE_LEN: usize = 65535;

/// NIP-44 padded length for an unpadded message length (power-of-2 chunking).
pub fn calc_padded_len(unpadded_len: usize) -> Result<usize> {
    if unpadded_len == 0 {
        return Err(Error::Padding("message too short"));
    }
    if unpadded_len > MAX_MESSAGE_LEN {
        return Err(Error::Padding("message too long"));
    }
    if unpadded_len <= 32 {
        return Ok(32);
    }
    let next_pow2 = (unpadded_len as u32).next_power_of_two();
    let chunk = core::cmp::max(32u32, next_pow2 >> 3) as usize;
    Ok(unpadded_len.div_ceil(chunk) * chunk)
}

/// `len(2B BE) || message || zero-pad` to `2 + calc_padded_len(len)`.
pub fn pad(message: &[u8]) -> Result<Vec<u8>> {
    let len = message.len();
    if len == 0 {
        return Err(Error::Padding("message too short"));
    }
    if len > MAX_MESSAGE_LEN {
        return Err(Error::Padding("message too long"));
    }
    let padded_len = calc_padded_len(len)?;
    let mut out = alloc::vec![0u8; 2 + padded_len];
    out[0] = ((len >> 8) & 0xff) as u8;
    out[1] = (len & 0xff) as u8;
    out[2..2 + len].copy_from_slice(message);
    Ok(out)
}

/// Reverse of [`pad`].
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 2 + MIN_PADDED_LEN {
        return Err(Error::Padding("padded message too short"));
    }
    let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if len == 0 || len > MAX_MESSAGE_LEN {
        return Err(Error::Padding("invalid message length"));
    }
    let expected = calc_padded_len(len)?;
    if padded.len() != 2 + expected {
        return Err(Error::Padding("invalid padding"));
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Derive the 32-byte conversation key from my secret and the peer's x-only key.
pub fn derive_conversation_key(my_secret: &[u8; 32], peer_xonly: &[u8; 32]) -> Result<[u8; 32]> {
    let shared_x = secp::ecdh_x(my_secret, peer_xonly)?;
    let my_pub = secp::xonly_public_key(my_secret)?;

    // salt = the two x-only pubkeys concatenated in ascending lexicographic order
    let mut salt = [0u8; 64];
    if my_pub[..] <= peer_xonly[..] {
        salt[..32].copy_from_slice(&my_pub);
        salt[32..].copy_from_slice(peer_xonly);
    } else {
        salt[..32].copy_from_slice(peer_xonly);
        salt[32..].copy_from_slice(&my_pub);
    }

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_x);
    let mut okm = [0u8; 32];
    hk.expand(b"nip44-v2", &mut okm)
        .map_err(|_| Error::Secp("hkdf expand"))?;
    Ok(okm)
}

fn derive_message_key(conversation_key: &[u8; 32], nonce: &[u8]) -> Result<[u8; 76]> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), conversation_key);
    let mut okm = [0u8; 76];
    hk.expand(b"", &mut okm)
        .map_err(|_| Error::Secp("hkdf expand"))?;
    Ok(okm)
}

fn aead_for(message_key: &[u8; 76]) -> (ChaCha20Poly1305, [u8; 12]) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key[0..32]));
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&message_key[32..44]);
    (cipher, nonce)
}

/// Encrypt with a pre-derived conversation key and an explicit 24-byte nonce.
/// Byte-identical to the reference SDK's `encryptWithKey` for the same nonce.
pub fn encrypt_with_key_nonce(
    conversation_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<alloc::string::String> {
    if plaintext.len() > MAX_MESSAGE_LEN {
        return Err(Error::Padding("message too long"));
    }
    let padded = pad(plaintext)?;
    let mk = derive_message_key(conversation_key, nonce)?;
    let (cipher, chacha_nonce) = aead_for(&mk);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&chacha_nonce), padded.as_ref())
        .map_err(|_| Error::Decrypt("aead encrypt"))?;

    let mut payload = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(payload))
}

/// Decrypt a base64 NIP-44 payload with a pre-derived conversation key.
pub fn decrypt_with_key(conversation_key: &[u8; 32], payload_b64: &str) -> Result<Vec<u8>> {
    let payload = STANDARD
        .decode(payload_b64)
        .map_err(|e| Error::Decode(alloc::format!("base64: {e}")))?;
    if payload.len() < 1 + NONCE_SIZE + MIN_PADDED_LEN + MAC_SIZE {
        return Err(Error::Malformed("nip44 payload too short"));
    }
    if payload[0] != VERSION {
        return Err(Error::Malformed("nip44 unsupported version"));
    }
    let nonce = &payload[1..1 + NONCE_SIZE];
    let ciphertext = &payload[1 + NONCE_SIZE..];
    let mk = derive_message_key(conversation_key, nonce)?;
    let (cipher, chacha_nonce) = aead_for(&mk);
    let padded = cipher
        .decrypt(Nonce::from_slice(&chacha_nonce), ciphertext)
        .map_err(|_| Error::Decrypt("aead: bad tag"))?;
    unpad(&padded)
}

/// Convenience: derive the conversation key then decrypt.
pub fn decrypt(my_secret: &[u8; 32], peer_xonly: &[u8; 32], payload_b64: &str) -> Result<Vec<u8>> {
    let ck = derive_conversation_key(my_secret, peer_xonly)?;
    decrypt_with_key(&ck, payload_b64)
}
