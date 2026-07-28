//! # unicity-nostr
//!
//! A Rust port of the Unicity Nostr protocol, **wire-compatible with the deployed
//! TypeScript SDK** (`@unicitylabs/nostr-js-sdk` v0.6.0). Every crypto/protocol
//! module is validated against golden vectors generated from that SDK (see
//! `tests/vectors.rs`).
//!
//! The crate is deliberately **transport-free** (no relay/WebSocket code) and
//! **custody-agnostic** ([`Signer`]), so it can be consumed both by a wallet
//! capsule (holding keys) and a messaging capsule (holding a remote signer) in
//! the AOS/Astrid design, and compiled to `wasm32-unknown-unknown`.
//!
//! ## Compatibility notes
//! * NIP-44 here is the **Unicity/TS AEAD variant**, not official NIP-44 v2, and
//!   not the (incompatible) Java SDK variant.
//! * NIP-04 uses `SHA-256(ECDH_x)` as the AES key (non-standard) with a `gz:`
//!   GZIP extension for large messages.
//!
//! ## Not yet ported (roadmap)
//! NIP-17 gift-wrap DMs, UNIP-01 nametag bindings + resolution, Filter, the
//! multi-relay client (transport), NIP-29 group chat, token/payment protocols.

extern crate alloc;

pub mod crypto;
pub mod error;
pub mod event;
pub mod keys;
pub mod kinds;
pub mod nip17;
pub mod signer;

pub use error::{Error, Result};
pub use event::{Event, Tag};
pub use keys::Keypair;
pub use nip17::{GiftWrapParams, PrivateMessage, Rumor};
pub use signer::{LocalSigner, Signer};
