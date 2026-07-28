//! NIP-04 — the **Unicity variant**, a port of `nostr-js-sdk/src/crypto/nip04.ts`.
//! Non-standard: the AES key is `SHA-256(ECDH_x)` (canonical NIP-04 uses the raw x).
//!
//! * AES-256-CBC, PKCS#7 padding, random 16-byte IV
//! * wire format `base64(ciphertext) ?iv= base64(iv)`
//! * messages > 1024 bytes are GZIP-compressed (if that shrinks them) and the
//!   whole string is prefixed with `gz:`
//!
//! GZIP output is not byte-identical to Node's zlib, so cross-impl parity is
//! verified on the **decrypt** side (we decode a TS-produced payload); our own
//! gzip encode path is exercised only by round-trip tests.

use alloc::string::String;
use alloc::vec::Vec;

use aes::Aes256;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

use crate::crypto::secp;
use crate::error::{Error, Result};

const COMPRESSION_THRESHOLD: usize = 1024;
const COMPRESSION_PREFIX: &str = "gz:";

type Enc = cbc::Encryptor<Aes256>;
type Dec = cbc::Decryptor<Aes256>;

/// NIP-04 shared secret = `SHA-256(ECDH_x)` (the AES-256 key).
pub fn derive_shared_secret(my_secret: &[u8; 32], peer_xonly: &[u8; 32]) -> Result<[u8; 32]> {
    let x = secp::ecdh_x(my_secret, peer_xonly)?;
    Ok(Sha256::digest(x).into())
}

fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    Enc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    Dec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("cbc padding"))
}

fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data)
        .map_err(|e| Error::Gzip(alloc::format!("{e}")))?;
    e.finish().map_err(|e| Error::Gzip(alloc::format!("{e}")))
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| Error::Gzip(alloc::format!("{e}")))?;
    Ok(out)
}

fn format(ciphertext: &[u8], iv: &[u8; 16], compressed: bool) -> String {
    let body = alloc::format!("{}?iv={}", STANDARD.encode(ciphertext), STANDARD.encode(iv));
    if compressed {
        alloc::format!("{COMPRESSION_PREFIX}{body}")
    } else {
        body
    }
}

/// Encrypt without compression, using a caller-supplied IV.
/// Byte-identical to the reference SDK for sub-threshold messages + the same IV.
pub fn encrypt_with_iv(
    my_secret: &[u8; 32],
    peer_xonly: &[u8; 32],
    message: &str,
    iv: &[u8; 16],
) -> Result<String> {
    let secret = derive_shared_secret(my_secret, peer_xonly)?;
    let ct = aes_cbc_encrypt(&secret, iv, message.as_bytes());
    Ok(format(&ct, iv, false))
}

/// Encrypt with the reference SDK's auto-compression rule (GZIP when the message
/// exceeds 1024 bytes and compression actually shrinks it). Used for round-trip
/// tests; the gzip bytes are not guaranteed identical to Node's.
pub fn encrypt_auto_with_iv(
    my_secret: &[u8; 32],
    peer_xonly: &[u8; 32],
    message: &str,
    iv: &[u8; 16],
) -> Result<String> {
    let secret = derive_shared_secret(my_secret, peer_xonly)?;
    let plaintext = message.as_bytes();
    let (data, compressed) = if plaintext.len() > COMPRESSION_THRESHOLD {
        let c = gzip(plaintext)?;
        if c.len() < plaintext.len() {
            (c, true)
        } else {
            (plaintext.to_vec(), false)
        }
    } else {
        (plaintext.to_vec(), false)
    };
    let ct = aes_cbc_encrypt(&secret, iv, &data);
    Ok(format(&ct, iv, compressed))
}

/// Decrypt a NIP-04 payload string (handles the `gz:` prefix and `?iv=` framing).
pub fn decrypt(my_secret: &[u8; 32], peer_xonly: &[u8; 32], payload: &str) -> Result<String> {
    let (content, compressed) = match payload.strip_prefix(COMPRESSION_PREFIX) {
        Some(rest) => (rest, true),
        None => (payload, false),
    };
    let (ct_b64, iv_b64) = content
        .split_once("?iv=")
        .ok_or(Error::Malformed("nip04 missing ?iv="))?;
    let ct = STANDARD
        .decode(ct_b64)
        .map_err(|e| Error::Decode(alloc::format!("base64 ct: {e}")))?;
    let iv_vec = STANDARD
        .decode(iv_b64)
        .map_err(|e| Error::Decode(alloc::format!("base64 iv: {e}")))?;
    let iv: [u8; 16] = iv_vec
        .try_into()
        .map_err(|_| Error::InvalidLength("iv != 16"))?;

    let secret = derive_shared_secret(my_secret, peer_xonly)?;
    let mut plaintext = aes_cbc_decrypt(&secret, &iv, &ct)?;
    if compressed {
        plaintext = gunzip(&plaintext)?;
    }
    String::from_utf8(plaintext).map_err(|_| Error::Utf8)
}
