//! Bech32 (NIP-19 `npub`/`nsec`) — a direct port of `nostr-js-sdk/src/crypto/bech32.ts`
//! so encoding is byte-identical to the reference SDK. Standard BIP-173 bech32
//! (NOT bech32m) with the Nostr charset.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &c in bytes {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in bytes {
        out.push(c & 31);
    }
    out
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut v = hrp_expand(hrp);
    v.extend_from_slice(data);
    polymod(&v) == 1
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut v = hrp_expand(hrp);
    v.extend_from_slice(data);
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let m = polymod(&v) ^ 1;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((m >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

/// Convert between bit widths. `None` on invalid input, mirroring the TS `convertBits`.
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;
    for &value in data {
        let value = value as u32;
        if (value >> from_bits) != 0 {
            return None;
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encode `data` under human-readable prefix `hrp`.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
    let values = convert_bits(data, 8, 5, true).ok_or(Error::Malformed("bech32 convert_bits"))?;
    let checksum = create_checksum(hrp, &values);
    let mut s = String::with_capacity(hrp.len() + 1 + values.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &v in values.iter().chain(checksum.iter()) {
        s.push(CHARSET[v as usize] as char);
    }
    Ok(s)
}

/// Decode a bech32 string into `(hrp, data_bytes)`.
pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
    let lower = s.to_ascii_lowercase();
    let pos = lower
        .rfind('1')
        .ok_or(Error::Malformed("bech32 no separator"))?;
    if pos < 1 || pos + 7 > lower.len() || lower.len() > 90 {
        return Err(Error::Malformed("bech32 length"));
    }
    let hrp = &lower[..pos];
    let data_chars = &lower[pos + 1..];
    let mut data = Vec::with_capacity(data_chars.len());
    for ch in data_chars.bytes() {
        let idx = CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or(Error::Malformed("bech32 bad char"))?;
        data.push(idx as u8);
    }
    if !verify_checksum(hrp, &data) {
        return Err(Error::Malformed("bech32 checksum"));
    }
    let without = &data[..data.len() - 6];
    let converted =
        convert_bits(without, 5, 8, false).ok_or(Error::Malformed("bech32 convert_bits"))?;
    Ok((String::from(hrp), converted))
}

/// Encode a 32-byte x-only public key as `npub`.
pub fn encode_npub(public_key: &[u8; 32]) -> Result<String> {
    encode("npub", public_key)
}

/// Encode a 32-byte private key as `nsec`.
pub fn encode_nsec(private_key: &[u8; 32]) -> Result<String> {
    encode("nsec", private_key)
}

/// Decode an `npub` into 32 bytes.
pub fn decode_npub(npub: &str) -> Result<[u8; 32]> {
    let (hrp, data) = decode(npub)?;
    if hrp != "npub" {
        return Err(Error::Malformed("expected npub"));
    }
    data.try_into()
        .map_err(|_| Error::InvalidLength("npub != 32 bytes"))
}

/// Decode an `nsec` into 32 bytes.
pub fn decode_nsec(nsec: &str) -> Result<[u8; 32]> {
    let (hrp, data) = decode(nsec)?;
    if hrp != "nsec" {
        return Err(Error::Malformed("expected nsec"));
    }
    data.try_into()
        .map_err(|_| Error::InvalidLength("nsec != 32 bytes"))
}
