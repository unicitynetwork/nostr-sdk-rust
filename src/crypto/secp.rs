//! secp256k1 primitives shared by NIP-04 and NIP-44: x-only pubkey derivation
//! and the ECDH x-coordinate. Matches the reference SDK, which reconstructs the
//! peer's x-only key as an **even-y** point (`0x02 || x`) before ECDH.

use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};

use crate::error::{Error, Result};

/// Derive the 32-byte x-only (BIP-340) public key from a 32-byte secret key.
pub fn xonly_public_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_slice(secret).map_err(|_| Error::Secp("invalid secret key"))?;
    let point = sk.public_key().to_encoded_point(true); // compressed: 0x02/0x03 || x
    let x = point.x().ok_or(Error::Secp("no x coordinate"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x.as_slice());
    Ok(out)
}

/// Reconstruct a peer's public key from its 32-byte x-only form, forcing even y
/// (`0x02` prefix) exactly as the reference SDK does.
fn peer_public_key(peer_xonly: &[u8; 32]) -> Result<PublicKey> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(peer_xonly);
    PublicKey::from_sec1_bytes(&compressed).map_err(|_| Error::Secp("invalid peer public key"))
}

/// Compute the ECDH shared x-coordinate: `x( my_secret * peerPoint )`, where
/// `peerPoint` is the even-y reconstruction of `peer_xonly`.
///
/// This is the raw shared secret used (directly by NIP-44's HKDF, and after a
/// SHA-256 by NIP-04). Note the x-coordinate is sign-independent, so forcing
/// even-y on the peer key keeps ECDH symmetric between the two parties.
pub fn ecdh_x(my_secret: &[u8; 32], peer_xonly: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_slice(my_secret).map_err(|_| Error::Secp("invalid secret key"))?;
    let peer = peer_public_key(peer_xonly)?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}
