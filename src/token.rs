//! Unicity token-transfer events (kind 31113), a port of
//! `token/TokenTransferProtocol.ts`. The content is NIP-04-encrypted and prefixed
//! `token_transfer:`; everything routes through the [`Signer`] seam.
//!
//! This is the Nostr *messaging* layer only — the token payload itself
//! (mint/settlement) is the concern of the Unicity token engine, not this crate.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::nip04;
use crate::error::{Error, Result};
use crate::event::{Event, Tag};
use crate::kinds;
use crate::signer::Signer;

const PREFIX: &str = "token_transfer:";
const TYPE: &str = "token_transfer";

/// Optional metadata tags for a token transfer.
#[derive(Clone, Debug, Default)]
pub struct TokenTransferOptions<'a> {
    /// Amount (decimal string), surfaced in an `amount` tag for relay filtering.
    pub amount: Option<&'a str>,
    /// Token symbol, surfaced in a `symbol` tag.
    pub symbol: Option<&'a str>,
    /// Correlate this transfer with a payment request (adds an `e` reply tag).
    pub reply_to_event_id: Option<&'a str>,
}

/// Build a signed token-transfer event (kind 31113) carrying `token_json`,
/// NIP-04-encrypted to `recipient_xonly`.
pub fn create_token_transfer_event<S: Signer>(
    signer: &S,
    recipient_xonly: &[u8; 32],
    token_json: &str,
    opts: &TokenTransferOptions,
    iv: &[u8; 16],
    created_at: i64,
) -> Result<Event> {
    let secret = signer.nip04_shared_secret(recipient_xonly)?;
    let message = alloc::format!("{PREFIX}{token_json}");
    let content = nip04::encrypt_auto_with_secret_iv(&secret, iv, &message)?;

    let mut tags: Vec<Tag> = vec![
        vec!["p".to_string(), hex::encode(recipient_xonly)],
        vec!["type".to_string(), TYPE.to_string()],
    ];
    if let Some(a) = opts.amount {
        tags.push(vec!["amount".to_string(), a.to_string()]);
    }
    if let Some(s) = opts.symbol {
        tags.push(vec!["symbol".to_string(), s.to_string()]);
    }
    if let Some(r) = opts.reply_to_event_id.filter(|r| !r.is_empty()) {
        tags.push(vec![
            "e".to_string(),
            r.to_string(),
            String::new(),
            "reply".to_string(),
        ]);
    }
    Event::create(signer, kinds::TOKEN_TRANSFER, tags, content, created_at)
}

/// Decrypt and return the token JSON from a token-transfer event.
pub fn parse_token_transfer<S: Signer>(signer: &S, event: &Event) -> Result<String> {
    if !is_token_transfer(event) {
        return Err(Error::Malformed("not a token transfer"));
    }
    let peer = super::protocol_peer(signer, event)?;
    let secret = signer.nip04_shared_secret(&peer)?;
    let decrypted = nip04::decrypt_with_secret(&secret, &event.content)?;
    decrypted
        .strip_prefix(PREFIX)
        .map(String::from)
        .ok_or(Error::Malformed("bad token_transfer prefix"))
}

/// True if `event` is a token transfer (kind 31113 + `type` tag).
pub fn is_token_transfer(event: &Event) -> bool {
    event.kind == kinds::TOKEN_TRANSFER && event.tag_value("type") == Some(TYPE)
}

/// `amount` tag value, if present.
pub fn amount(event: &Event) -> Option<&str> {
    event.tag_value("amount")
}

/// `symbol` tag value, if present.
pub fn symbol(event: &Event) -> Option<&str> {
    event.tag_value("symbol")
}

/// Correlated payment-request event id (`e` tag), if present.
pub fn reply_to_event_id(event: &Event) -> Option<&str> {
    event.tag_value("e")
}

/// Recipient pubkey (`p` tag), if present.
pub fn recipient(event: &Event) -> Option<&str> {
    event.tag_value("p")
}
