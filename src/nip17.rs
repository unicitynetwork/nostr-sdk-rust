//! NIP-17 gift-wrapped private direct messages, a port of
//! `nostr-js-sdk/src/messaging/nip17.ts`.
//!
//! Three layers:
//! 1. **Rumor** (kind 14 chat / 15 receipt) — unsigned, real timestamp, the actual content.
//! 2. **Seal** (kind 13) — signed by the sender, NIP-44-encrypts the rumor JSON to the recipient.
//! 3. **Gift wrap** (kind 1059) — signed by a fresh ephemeral key, NIP-44-encrypts the seal JSON.
//!
//! Everything routes through the [`Signer`] seam, so a network-facing component
//! need never hold the identity key — the only local secret is the throwaway
//! ephemeral key used for the outer wrap. Because the wrap uses a random
//! ephemeral key and randomized timestamps, gift wraps are non-deterministic;
//! [`create_gift_wrap`] therefore takes the entropy explicitly ([`GiftWrapParams`])
//! so callers control it (a host RNG/clock in production; fixed values in tests).

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::crypto::{nip44, schnorr};
use crate::error::{Error, Result};
use crate::event::{Event, Tag};
use crate::keys::Keypair;
use crate::kinds;
use crate::signer::{LocalSigner, Signer};

/// An unsigned inner event (NIP-17 rumor). Field order matches the reference
/// SDK's object so `serde_json` reproduces its `JSON.stringify` shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rumor {
    /// Rumor id (SHA-256 of the canonical serialization).
    pub id: String,
    /// Real sender x-only public key (hex).
    pub pubkey: String,
    /// Real timestamp (seconds).
    pub created_at: i64,
    /// Kind (14 chat, 15 receipt).
    pub kind: u32,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Content.
    pub content: String,
}

/// A decrypted private message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    /// Gift-wrap event id (for dedup).
    pub event_id: String,
    /// Real sender x-only public key (hex), taken from the seal.
    pub sender_pubkey: String,
    /// Recipient x-only public key (hex).
    pub recipient_pubkey: String,
    /// Message content.
    pub content: String,
    /// Rumor timestamp.
    pub timestamp: i64,
    /// Rumor kind.
    pub kind: u32,
    /// Reply-to event id, if the rumor carried an `e` tag.
    pub reply_to_event_id: Option<String>,
}

/// Caller-supplied entropy + timestamps for a gift wrap. In production these come
/// from a secure RNG and the system clock; in tests they are fixed for determinism.
pub struct GiftWrapParams<'a> {
    /// Message content.
    pub content: &'a str,
    /// Optional reply-to event id (adds an `e` tag to the rumor).
    pub reply_to: Option<&'a str>,
    /// Real timestamp for the rumor.
    pub rumor_created_at: i64,
    /// Randomized timestamp for the seal.
    pub seal_created_at: i64,
    /// Randomized timestamp for the gift wrap.
    pub wrap_created_at: i64,
    /// Ephemeral secret key for the outer wrap (throwaway).
    pub ephemeral_secret: [u8; 32],
    /// NIP-44 nonce for the seal encryption.
    pub seal_nonce: [u8; 24],
    /// NIP-44 nonce for the gift-wrap encryption.
    pub wrap_nonce: [u8; 24],
}

fn rumor_json(rumor: &Rumor) -> String {
    serde_json::to_string(rumor).expect("rumor serialization is infallible")
}

/// Build a signed gift wrap (kind 1059) carrying a chat rumor (kind 14) from
/// `sender` to `recipient_xonly`.
pub fn create_gift_wrap<S: Signer>(
    sender: &S,
    recipient_xonly: &[u8; 32],
    params: &GiftWrapParams,
) -> Result<Event> {
    let sender_pub = hex::encode(sender.public_key());
    let recipient_hex = hex::encode(recipient_xonly);

    // 1. Rumor (unsigned, real timestamp).
    let mut tags: Vec<Tag> = vec![vec!["p".to_string(), recipient_hex.clone()]];
    if let Some(reply) = params.reply_to {
        tags.push(vec![
            "e".to_string(),
            reply.to_string(),
            String::new(),
            "reply".to_string(),
        ]);
    }
    let rumor_id = Event::calculate_id(
        &sender_pub,
        params.rumor_created_at,
        kinds::CHAT_MESSAGE,
        &tags,
        params.content,
    );
    let rumor = Rumor {
        id: rumor_id,
        pubkey: sender_pub.clone(),
        created_at: params.rumor_created_at,
        kind: kinds::CHAT_MESSAGE,
        tags,
        content: params.content.to_string(),
    };

    // 2. Seal (kind 13), signed by sender, encrypting the rumor to the recipient.
    let seal_conv = sender.nip44_conversation_key(recipient_xonly)?;
    let seal_content = nip44::encrypt_with_key_nonce(
        &seal_conv,
        &params.seal_nonce,
        rumor_json(&rumor).as_bytes(),
    )?;
    let seal_id = Event::calculate_id(
        &sender_pub,
        params.seal_created_at,
        kinds::SEAL,
        &[],
        &seal_content,
    );
    let seal_sig = sender.schnorr_sign(&hex_id(&seal_id)?)?;
    let seal = Event {
        id: seal_id,
        pubkey: sender_pub,
        created_at: params.seal_created_at,
        kind: kinds::SEAL,
        tags: Vec::new(),
        content: seal_content,
        sig: hex::encode(seal_sig),
    };

    // 3. Gift wrap (kind 1059), signed by the ephemeral key, encrypting the seal.
    let ephemeral = LocalSigner::new(Keypair::from_secret(params.ephemeral_secret)?);
    let eph_pub = hex::encode(ephemeral.public_key());
    let seal_json = serde_json::to_string(&seal).expect("event serialization is infallible");
    let wrap_conv = ephemeral.nip44_conversation_key(recipient_xonly)?;
    let wrap_content =
        nip44::encrypt_with_key_nonce(&wrap_conv, &params.wrap_nonce, seal_json.as_bytes())?;
    let wrap_tags: Vec<Tag> = vec![vec!["p".to_string(), recipient_hex]];
    let wrap_id = Event::calculate_id(
        &eph_pub,
        params.wrap_created_at,
        kinds::GIFT_WRAP,
        &wrap_tags,
        &wrap_content,
    );
    let wrap_sig = ephemeral.schnorr_sign(&hex_id(&wrap_id)?)?;
    Ok(Event {
        id: wrap_id,
        pubkey: eph_pub,
        created_at: params.wrap_created_at,
        kind: kinds::GIFT_WRAP,
        tags: wrap_tags,
        content: wrap_content,
        sig: hex::encode(wrap_sig),
    })
}

/// Unwrap a gift wrap into a [`PrivateMessage`], using the recipient's signer to
/// derive the two conversation keys. The seal signature is verified.
pub fn unwrap<S: Signer>(recipient: &S, gift_wrap: &Event) -> Result<PrivateMessage> {
    if gift_wrap.kind != kinds::GIFT_WRAP {
        return Err(Error::Malformed("event is not a gift wrap"));
    }

    // Decrypt the seal using the gift wrap's ephemeral pubkey.
    let ephemeral_pub = hex_key(&gift_wrap.pubkey)?;
    let wrap_conv = recipient.nip44_conversation_key(&ephemeral_pub)?;
    let seal_bytes = nip44::decrypt_with_key(&wrap_conv, &gift_wrap.content)?;
    let seal: Event = serde_json::from_slice(&seal_bytes)
        .map_err(|e| Error::Decode(alloc::format!("seal json: {e}")))?;
    if seal.kind != kinds::SEAL {
        return Err(Error::Malformed("inner event is not a seal"));
    }

    // Verify the seal signature (over its stated id, matching the reference SDK).
    let seal_id = hex_id(&seal.id)?;
    let seal_sig: [u8; 64] = hex::decode(&seal.sig)
        .map_err(|e| Error::Decode(alloc::format!("seal sig: {e}")))?
        .try_into()
        .map_err(|_| Error::InvalidLength("seal sig != 64"))?;
    let seal_pub = hex_key(&seal.pubkey)?;
    if !schnorr::verify(&seal_sig, &seal_id, &seal_pub) {
        return Err(Error::Decrypt("seal signature verification failed"));
    }

    // Decrypt the rumor using the seal author's pubkey.
    let seal_conv = recipient.nip44_conversation_key(&seal_pub)?;
    let rumor_bytes = nip44::decrypt_with_key(&seal_conv, &seal.content)?;
    let rumor: Rumor = serde_json::from_slice(&rumor_bytes)
        .map_err(|e| Error::Decode(alloc::format!("rumor json: {e}")))?;

    let reply_to_event_id = rumor
        .tags
        .iter()
        .find(|t| t.first().map(String::as_str) == Some("e"))
        .and_then(|t| t.get(1))
        .cloned();

    Ok(PrivateMessage {
        event_id: gift_wrap.id.clone(),
        sender_pubkey: seal.pubkey,
        recipient_pubkey: hex::encode(recipient.public_key()),
        content: rumor.content,
        timestamp: rumor.created_at,
        kind: rumor.kind,
        reply_to_event_id,
    })
}

fn hex_id(id_hex: &str) -> Result<[u8; 32]> {
    hex::decode(id_hex)
        .map_err(|e| Error::Decode(alloc::format!("hex id: {e}")))?
        .try_into()
        .map_err(|_| Error::InvalidLength("id != 32"))
}

fn hex_key(k: &str) -> Result<[u8; 32]> {
    hex::decode(k)
        .map_err(|e| Error::Decode(alloc::format!("hex key: {e}")))?
        .try_into()
        .map_err(|_| Error::InvalidLength("pubkey != 32"))
}
