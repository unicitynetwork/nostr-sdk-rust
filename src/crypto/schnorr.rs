//! BIP-340 Schnorr, matching `nostr-js-sdk/src/crypto/schnorr.ts` (which uses
//! `@noble/curves` schnorr). Signing is exposed with an explicit `aux_rand` so
//! callers can produce deterministic signatures (aux = zeros) that are
//! byte-identical to the reference SDK when it is given the same aux.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};

use crate::error::{Error, Result};

/// x-only public key from a 32-byte secret (BIP-340).
pub fn public_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SigningKey::from_bytes(secret).map_err(|_| Error::Secp("invalid secret key"))?;
    let bytes = sk.verifying_key().to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

/// Sign a 32-byte message (the event id) with an explicit 32-byte `aux_rand`.
/// With `aux_rand = [0; 32]` this is deterministic and matches the reference SDK
/// when it signs with the same aux.
pub fn sign_with_aux(
    message: &[u8; 32],
    secret: &[u8; 32],
    aux_rand: &[u8; 32],
) -> Result<[u8; 64]> {
    let sk = SigningKey::from_bytes(secret).map_err(|_| Error::Secp("invalid secret key"))?;
    let sig = sk
        .sign_raw(message, aux_rand)
        .map_err(|_| Error::Secp("schnorr sign failed"))?;
    Ok(sig.to_bytes())
}

/// Deterministic sign with `aux_rand = [0; 32]`.
pub fn sign(message: &[u8; 32], secret: &[u8; 32]) -> Result<[u8; 64]> {
    sign_with_aux(message, secret, &[0u8; 32])
}

/// Verify a 64-byte BIP-340 signature over a 32-byte message against an x-only key.
pub fn verify(signature: &[u8; 64], message: &[u8; 32], public_key: &[u8; 32]) -> bool {
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match Signature::try_from(&signature[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Use verify_raw (not the `Verifier` trait): Verifier::verify pre-hashes the
    // message with SHA-256, but Nostr/BIP-340 here signs the 32-byte event id
    // directly (matching sign_raw and the reference SDK).
    vk.verify_raw(message, &sig).is_ok()
}
