//! # unicity-nostr
//!
//! A Rust port of the Unicity Nostr protocol, **wire-compatible with the deployed
//! TypeScript SDK** (`@unicitylabs/nostr-js-sdk` v0.6.0). Every crypto/protocol
//! module is validated against golden vectors generated from that SDK (see
//! `tests/vectors.rs`).
//!
//! The protocol/crypto layer is deliberately **transport-free** (no relay/WebSocket
//! code) and **custody-agnostic** ([`Signer`]), so keys and networking can live in
//! separate components: a key-holding process and a network-facing process that
//! proxies signing to it. The core compiles to `wasm32-unknown-unknown`.
//!
//! ## Compatibility notes
//! * NIP-44 here is the **Unicity/TS AEAD variant**, not official NIP-44 v2, and
//!   not the (incompatible) Java SDK variant.
//! * NIP-04 uses `SHA-256(ECDH_x)` as the AES key (non-standard) with a `gz:`
//!   GZIP extension for large messages.
//!
//! ## Not yet ported (roadmap)
//! Multi-relay fan-out + reconnect/keepalive supervision, token/payment protocols.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod binding;
pub mod client;
pub mod crypto;
pub mod error;
pub mod event;
pub mod filter;
pub mod keys;
pub mod kinds;
pub mod nametag;
pub mod nip17;
pub mod payment;
pub mod signer;
pub mod token;

pub use error::{Error, Result};
pub use event::{Event, Tag};
pub use filter::{Filter, FilterBuilder};
pub use keys::Keypair;
pub use nip17::{GiftWrapParams, PrivateMessage, Rumor};
pub use signer::{LocalSigner, Signer};

/// Determine the NIP-04 decryption peer for a directed (token/payment) event:
/// if we authored it, the peer is the `p`-tagged recipient; otherwise the author.
pub(crate) fn protocol_peer<S: Signer>(signer: &S, event: &Event) -> Result<[u8; 32]> {
    use alloc::string::ToString;
    let me = hex::encode(signer.public_key());
    let peer_hex = if event.pubkey == me {
        event
            .tag_value("p")
            .ok_or(Error::Malformed("no recipient tag"))?
            .to_string()
    } else {
        event.pubkey.clone()
    };
    hex::decode(&peer_hex)
        .map_err(|e| Error::Decode(alloc::format!("hex peer: {e}")))?
        .try_into()
        .map_err(|_| Error::InvalidLength("peer != 32"))
}
