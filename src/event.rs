//! Nostr events (NIP-01). The event id is `SHA-256` over the canonical compact
//! JSON array `[0, pubkey, created_at, kind, tags, content]` — byte-identical to
//! the reference SDK's `JSON.stringify` (serde_json's compact output escapes the
//! same set: `"`, `\`, control chars; non-ASCII and `/` left raw).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::signer::Signer;

/// A tag is a list of strings whose first element is the tag name.
pub type Tag = Vec<String>;

/// A signed Nostr event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Event id — hex SHA-256 of the canonical serialization.
    pub id: String,
    /// Author x-only public key (hex).
    pub pubkey: String,
    /// Unix timestamp (seconds).
    pub created_at: i64,
    /// Event kind.
    pub kind: u32,
    /// Event tags.
    pub tags: Vec<Tag>,
    /// Event content.
    pub content: String,
    /// BIP-340 Schnorr signature (hex).
    pub sig: String,
}

impl Event {
    /// Compute the NIP-01 event id (hex) for the given fields.
    pub fn calculate_id(
        pubkey: &str,
        created_at: i64,
        kind: u32,
        tags: &[Tag],
        content: &str,
    ) -> String {
        // serde_json serializes a tuple as a compact JSON array with no spaces,
        // matching JS `JSON.stringify([0, pubkey, created_at, kind, tags, content])`.
        let serialized = serde_json::to_string(&(0u8, pubkey, created_at, kind, tags, content))
            .expect("event serialization is infallible");
        hex::encode(Sha256::digest(serialized.as_bytes()))
    }

    /// Build and sign an event with the given signer.
    pub fn create<S: Signer>(
        signer: &S,
        kind: u32,
        tags: Vec<Tag>,
        content: String,
        created_at: i64,
    ) -> Result<Event> {
        let pubkey = hex::encode(signer.public_key());
        let id = Event::calculate_id(&pubkey, created_at, kind, &tags, &content);
        let id_bytes: [u8; 32] = hex::decode(&id)
            .map_err(|e| Error::Decode(alloc::format!("hex id: {e}")))?
            .try_into()
            .map_err(|_| Error::InvalidLength("id != 32"))?;
        let sig = signer.schnorr_sign(&id_bytes)?;
        Ok(Event {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(sig),
        })
    }

    /// Verify the id recomputes and the Schnorr signature is valid.
    pub fn verify(&self) -> bool {
        let recomputed = Event::calculate_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if recomputed != self.id {
            return false;
        }
        let (id, sig, pubkey) = match (
            hex::decode(&self.id),
            hex::decode(&self.sig),
            hex::decode(&self.pubkey),
        ) {
            (Ok(i), Ok(s), Ok(p)) => (i, s, p),
            _ => return false,
        };
        let id: [u8; 32] = match id.try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig: [u8; 64] = match sig.try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let pubkey: [u8; 32] = match pubkey.try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        crate::crypto::schnorr::verify(&sig, &id, &pubkey)
    }

    /// First value of the first tag named `name`.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }
}
