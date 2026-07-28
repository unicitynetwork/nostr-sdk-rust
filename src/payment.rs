//! Unicity payment-request messaging over Nostr (kinds 31115 / 31116), a port of
//! `payment/PaymentRequestProtocol.ts`. NIP-04-encrypted content prefixed
//! `payment_request:` / `payment_request_response:`, routed through the [`Signer`].
//!
//! Request ids, deadlines, and IVs are supplied by the caller (a secure RNG / the
//! system clock in production), keeping the crate RNG/clock-free.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::Serialize;

use crate::crypto::nip04;
use crate::error::{Error, Result};
use crate::event::{Event, Tag};
use crate::kinds;
use crate::signer::Signer;

const REQUEST_PREFIX: &str = "payment_request:";
const RESPONSE_PREFIX: &str = "payment_request_response:";
const REQUEST_TYPE: &str = "payment_request";
const RESPONSE_TYPE: &str = "payment_request_response";

/// Response status for a declined/expired payment request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseStatus {
    /// Declined by the recipient.
    Declined,
    /// The request deadline passed.
    Expired,
}

impl ResponseStatus {
    /// Wire string (`DECLINED` / `EXPIRED`).
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseStatus::Declined => "DECLINED",
            ResponseStatus::Expired => "EXPIRED",
        }
    }

    /// Parse from the wire string.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "DECLINED" => Some(ResponseStatus::Declined),
            "EXPIRED" => Some(ResponseStatus::Expired),
            _ => None,
        }
    }
}

/// Parameters for a payment-request response.
#[derive(Clone, Debug)]
pub struct PaymentResponseParams<'a> {
    /// The request id being responded to.
    pub request_id: &'a str,
    /// The original request event id (adds an `e` reply tag).
    pub original_event_id: &'a str,
    /// Response status.
    pub status: ResponseStatus,
    /// Optional reason.
    pub reason: Option<&'a str>,
}

/// Parameters for a payment request. `amount` is a decimal string (smallest
/// units); `request_id` and `deadline` (ms, `None` = no deadline) are caller-supplied.
#[derive(Clone, Debug)]
pub struct PaymentRequestParams<'a> {
    /// Amount in smallest units (decimal string).
    pub amount: &'a str,
    /// Coin id (hex token-type identifier).
    pub coin_id: &'a str,
    /// Optional human-readable message.
    pub message: Option<&'a str>,
    /// Nametag where tokens should be sent (the requester's).
    pub recipient_nametag: &'a str,
    /// Unique request id (caller-generated).
    pub request_id: &'a str,
    /// Deadline (ms since epoch); `None` = no deadline (serialized as `null`).
    pub deadline: Option<i64>,
}

#[derive(Serialize)]
struct RequestJson<'a> {
    amount: &'a str,
    #[serde(rename = "coinId")]
    coin_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(rename = "recipientNametag")]
    recipient_nametag: &'a str,
    #[serde(rename = "requestId")]
    request_id: &'a str,
    deadline: Option<i64>,
}

#[derive(Serialize)]
struct ResponseJson<'a> {
    #[serde(rename = "requestId")]
    request_id: &'a str,
    #[serde(rename = "originalEventId")]
    original_event_id: &'a str,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

/// A decrypted payment request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPaymentRequest {
    /// Amount (decimal string, smallest units).
    pub amount: String,
    /// Coin id.
    pub coin_id: String,
    /// Optional message.
    pub message: Option<String>,
    /// Requester's nametag.
    pub recipient_nametag: String,
    /// Request id.
    pub request_id: String,
    /// Sender (requester) pubkey (hex).
    pub sender_pubkey: String,
    /// Event timestamp (ms).
    pub timestamp: i64,
    /// Event id.
    pub event_id: String,
    /// Deadline (ms), or `None`.
    pub deadline: Option<i64>,
}

/// A decrypted payment-request response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPaymentRequestResponse {
    /// Original request id.
    pub request_id: String,
    /// Original request event id.
    pub original_event_id: String,
    /// Status.
    pub status: ResponseStatus,
    /// Optional reason.
    pub reason: Option<String>,
    /// Responder pubkey (hex).
    pub sender_pubkey: String,
    /// Response event id.
    pub event_id: String,
    /// Event timestamp (ms).
    pub timestamp: i64,
}

/// Build a signed payment-request event (kind 31115).
pub fn create_payment_request_event<S: Signer>(
    signer: &S,
    target_xonly: &[u8; 32],
    params: &PaymentRequestParams,
    iv: &[u8; 16],
    created_at: i64,
) -> Result<Event> {
    let json = serde_json::to_string(&RequestJson {
        amount: params.amount,
        coin_id: params.coin_id,
        message: params.message,
        recipient_nametag: params.recipient_nametag,
        request_id: params.request_id,
        deadline: params.deadline,
    })
    .expect("request json");
    let secret = signer.nip04_shared_secret(target_xonly)?;
    let content =
        nip04::encrypt_auto_with_secret_iv(&secret, iv, &alloc::format!("{REQUEST_PREFIX}{json}"))?;

    let mut tags: Vec<Tag> = vec![
        vec!["p".to_string(), hex::encode(target_xonly)],
        vec!["type".to_string(), REQUEST_TYPE.to_string()],
        vec!["amount".to_string(), params.amount.to_string()],
    ];
    if !params.recipient_nametag.is_empty() {
        tags.push(vec![
            "recipient".to_string(),
            params.recipient_nametag.to_string(),
        ]);
    }
    Event::create(signer, kinds::PAYMENT_REQUEST, tags, content, created_at)
}

/// Decrypt and parse a payment-request event.
pub fn parse_payment_request<S: Signer>(signer: &S, event: &Event) -> Result<ParsedPaymentRequest> {
    if !is_payment_request(event) {
        return Err(Error::Malformed("not a payment request"));
    }
    let json = decrypt_prefixed(signer, event, REQUEST_PREFIX)?;
    let v: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| Error::Decode(alloc::format!("request json: {e}")))?;
    Ok(ParsedPaymentRequest {
        amount: str_field(&v, "amount")?,
        coin_id: str_field(&v, "coinId")?,
        message: v.get("message").and_then(|x| x.as_str()).map(String::from),
        recipient_nametag: str_field(&v, "recipientNametag").unwrap_or_default(),
        request_id: str_field(&v, "requestId")?,
        sender_pubkey: event.pubkey.clone(),
        timestamp: event.created_at.saturating_mul(1000),
        event_id: event.id.clone(),
        deadline: v.get("deadline").and_then(|x| x.as_i64()),
    })
}

/// Build a signed payment-request response event (kind 31116).
pub fn create_payment_request_response_event<S: Signer>(
    signer: &S,
    target_xonly: &[u8; 32],
    params: &PaymentResponseParams,
    iv: &[u8; 16],
    created_at: i64,
) -> Result<Event> {
    let json = serde_json::to_string(&ResponseJson {
        request_id: params.request_id,
        original_event_id: params.original_event_id,
        status: params.status.as_str(),
        reason: params.reason,
    })
    .expect("response json");
    let secret = signer.nip04_shared_secret(target_xonly)?;
    let content = nip04::encrypt_auto_with_secret_iv(
        &secret,
        iv,
        &alloc::format!("{RESPONSE_PREFIX}{json}"),
    )?;

    let mut tags: Vec<Tag> = vec![
        vec!["p".to_string(), hex::encode(target_xonly)],
        vec!["type".to_string(), RESPONSE_TYPE.to_string()],
        vec!["status".to_string(), params.status.as_str().to_string()],
    ];
    if !params.original_event_id.is_empty() {
        tags.push(vec![
            "e".to_string(),
            params.original_event_id.to_string(),
            String::new(),
            "reply".to_string(),
        ]);
    }
    Event::create(
        signer,
        kinds::PAYMENT_REQUEST_RESPONSE,
        tags,
        content,
        created_at,
    )
}

/// Decrypt and parse a payment-request response event.
pub fn parse_payment_request_response<S: Signer>(
    signer: &S,
    event: &Event,
) -> Result<ParsedPaymentRequestResponse> {
    if event.kind != kinds::PAYMENT_REQUEST_RESPONSE {
        return Err(Error::Malformed("not a payment request response"));
    }
    let json = decrypt_prefixed(signer, event, RESPONSE_PREFIX)?;
    let v: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| Error::Decode(alloc::format!("response json: {e}")))?;
    let status = ResponseStatus::from_wire(&str_field(&v, "status")?)
        .ok_or(Error::Malformed("unknown response status"))?;
    Ok(ParsedPaymentRequestResponse {
        request_id: str_field(&v, "requestId")?,
        original_event_id: str_field(&v, "originalEventId")?,
        status,
        reason: v.get("reason").and_then(|x| x.as_str()).map(String::from),
        sender_pubkey: event.pubkey.clone(),
        event_id: event.id.clone(),
        timestamp: event.created_at.saturating_mul(1000),
    })
}

/// True if `event` is a payment request (kind 31115 + `type` tag).
pub fn is_payment_request(event: &Event) -> bool {
    event.kind == kinds::PAYMENT_REQUEST && event.tag_value("type") == Some(REQUEST_TYPE)
}

/// True if `event` is a payment-request response (kind 31116 + `type` tag).
pub fn is_payment_request_response(event: &Event) -> bool {
    event.kind == kinds::PAYMENT_REQUEST_RESPONSE && event.tag_value("type") == Some(RESPONSE_TYPE)
}

/// Format `amount` (smallest units) as a decimal string with `decimals` places,
/// trailing zeros trimmed.
pub fn format_amount(amount: u128, decimals: u32) -> String {
    let divisor = 10u128.pow(decimals);
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = alloc::format!("{:0width$}", frac, width = decimals as usize);
    let trimmed = frac_str.trim_end_matches('0');
    alloc::format!("{whole}.{trimmed}")
}

/// Parse a decimal string into smallest units with `decimals` places.
pub fn parse_amount(s: &str, decimals: u32) -> Result<u128> {
    let mult = 10u128.pow(decimals);
    let (whole_str, frac_str) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u128 = if whole_str.is_empty() {
        0
    } else {
        whole_str
            .parse()
            .map_err(|_| Error::Malformed("bad amount"))?
    };
    let dec = decimals as usize;
    let mut frac = String::from(frac_str);
    if frac.len() < dec {
        frac.push_str(&"0".repeat(dec - frac.len()));
    } else {
        frac.truncate(dec);
    }
    let frac_val: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|_| Error::Malformed("bad amount fraction"))?
    };
    Ok(whole * mult + frac_val)
}

fn decrypt_prefixed<S: Signer>(signer: &S, event: &Event, prefix: &str) -> Result<String> {
    let peer = super::protocol_peer(signer, event)?;
    let secret = signer.nip04_shared_secret(&peer)?;
    let decrypted = nip04::decrypt_with_secret(&secret, &event.content)?;
    decrypted
        .strip_prefix(prefix)
        .map(String::from)
        .ok_or(Error::Malformed("bad payment prefix"))
}

fn str_field(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(String::from)
        .ok_or(Error::Malformed("missing json field"))
}
