//! Nostr event kinds (standard NIP kinds + Unicity custom kinds), mirroring
//! `nostr-js-sdk/src/protocol/EventKinds.ts`.

/// NIP-01 profile metadata.
pub const PROFILE: u32 = 0;
/// NIP-01 short text note.
pub const TEXT_NOTE: u32 = 1;
/// NIP-02 contact list.
pub const CONTACTS: u32 = 3;
/// NIP-04 encrypted direct message.
pub const ENCRYPTED_DM: u32 = 4;
/// NIP-09 deletion.
pub const DELETION: u32 = 5;
/// NIP-25 reaction.
pub const REACTION: u32 = 7;
/// NIP-17 seal (signed, encrypts a rumor).
pub const SEAL: u32 = 13;
/// NIP-17 private chat message (rumor).
pub const CHAT_MESSAGE: u32 = 14;
/// NIP-17 read receipt (rumor).
pub const READ_RECEIPT: u32 = 15;
/// NIP-59 gift wrap.
pub const GIFT_WRAP: u32 = 1059;
/// NIP-65 relay list.
pub const RELAY_LIST: u32 = 10002;
/// NIP-42 client authentication.
pub const AUTH: u32 = 22242;
/// NIP-78 application data (used for UNIP-01 nametag/identity bindings).
pub const APP_DATA: u32 = 30078;

// Unicity custom kinds.
/// Unicity agent profile.
pub const AGENT_PROFILE: u32 = 31111;
/// Unicity agent location.
pub const AGENT_LOCATION: u32 = 31112;
/// Unicity token transfer.
pub const TOKEN_TRANSFER: u32 = 31113;
/// Unicity file metadata.
pub const FILE_METADATA: u32 = 31114;
/// Unicity payment request.
pub const PAYMENT_REQUEST: u32 = 31115;
/// Unicity payment request response.
pub const PAYMENT_REQUEST_RESPONSE: u32 = 31116;

/// Replaceable event (kind 0, 3, or 10000–19999).
pub fn is_replaceable(kind: u32) -> bool {
    kind == 0 || kind == 3 || (10000..20000).contains(&kind)
}

/// Ephemeral event (20000–29999).
pub fn is_ephemeral(kind: u32) -> bool {
    (20000..30000).contains(&kind)
}

/// Parameterized-replaceable event (30000–39999).
pub fn is_parameterized_replaceable(kind: u32) -> bool {
    (30000..40000).contains(&kind)
}
