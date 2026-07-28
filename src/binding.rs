//! UNIP-01 nametag/identity binding events (kind 30078) and the safety-critical
//! resolution algorithm, ported from `nostr-js-sdk` (`nametag/NametagBinding.ts`
//! plus `NostrClient.queryWithFirstSeenWins`).
//!
//! Resolution is transport-free here: [`resolve_owner`] takes the set of binding
//! events a relay returned and applies the exact UNIP-01 selection rule.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::event::{Event, Tag};
use crate::filter::Filter;
use crate::kinds;
use crate::nametag;
use crate::signer::Signer;

/// Extended identity fields for a richer binding (all optional).
#[derive(Clone, Debug, Default)]
pub struct IdentityBindingParams {
    /// 33-byte compressed secp256k1 public key (hex).
    pub public_key: Option<String>,
    /// L1 bech32 address.
    pub l1_address: Option<String>,
    /// DIRECT:// address.
    pub direct_address: Option<String>,
    /// PROXY:// address.
    pub proxy_address: Option<String>,
}

/// Parsed binding info (mirrors the reference SDK's `BindingInfo`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingInfo {
    /// Event author's 32-byte Nostr pubkey (hex).
    pub transport_pubkey: String,
    /// 33-byte compressed secp256k1 pubkey (hex), from content.
    pub public_key: Option<String>,
    /// L1 address, from content.
    pub l1_address: Option<String>,
    /// DIRECT:// address, from content.
    pub direct_address: Option<String>,
    /// PROXY:// address, from content.
    pub proxy_address: Option<String>,
    /// Plaintext nametag, from content (when present).
    pub nametag: Option<String>,
    /// Event timestamp in milliseconds.
    pub timestamp: i64,
}

#[derive(Serialize)]
struct BindingContent<'a> {
    nametag_hash: &'a str,
    address: &'a str,
    verified: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_nametag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nametag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l1_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_address: Option<&'a str>,
}

/// Build a signed nametag binding event (kind 30078) carrying the UNIP-01
/// single-owner marker. `verified` and `created_at` are supplied by the caller
/// (e.g. from the system clock). If `identity` is given, the plaintext nametag and
/// the (caller-computed) `encrypted_nametag` are embedded for public resolution +
/// recovery, matching the reference SDK.
pub fn create_binding_event<S: Signer>(
    signer: &S,
    nametag_id: &str,
    unicity_address: &str,
    verified: i64,
    created_at: i64,
    identity: Option<&IdentityBindingParams>,
    encrypted_nametag: Option<&str>,
) -> Result<Event> {
    if !nametag::is_valid_nametag(nametag_id) {
        return Err(Error::Malformed("invalid nametag"));
    }
    let hashed = nametag::hash_nametag(nametag_id);

    let mut tags: Vec<Tag> = vec![
        vec!["d".to_string(), hashed.clone()],
        vec!["L".to_string(), nametag::NAMETAG_MARKER_LABEL.to_string()],
        vec!["nametag".to_string(), hashed.clone()],
        vec!["t".to_string(), hashed.clone()],
        vec!["address".to_string(), unicity_address.to_string()],
        vec![
            "t".to_string(),
            nametag::hash_address_for_tag(unicity_address),
        ],
    ];

    let mut content = BindingContent {
        nametag_hash: &hashed,
        address: unicity_address,
        verified,
        encrypted_nametag: None,
        nametag: None,
        public_key: None,
        l1_address: None,
        direct_address: None,
        proxy_address: None,
    };

    if let Some(id) = identity {
        content.encrypted_nametag = encrypted_nametag;
        content.nametag = Some(nametag_id);
        if let Some(pk) = &id.public_key {
            content.public_key = Some(pk);
            tags.push(vec!["t".to_string(), nametag::hash_address_for_tag(pk)]);
            tags.push(vec!["pubkey".to_string(), pk.clone()]);
        }
        if let Some(l1) = &id.l1_address {
            content.l1_address = Some(l1);
            tags.push(vec!["t".to_string(), nametag::hash_address_for_tag(l1)]);
            tags.push(vec!["l1".to_string(), l1.clone()]);
        }
        if let Some(da) = &id.direct_address {
            content.direct_address = Some(da);
            tags.push(vec!["t".to_string(), nametag::hash_address_for_tag(da)]);
        }
        if let Some(pa) = &id.proxy_address {
            content.proxy_address = Some(pa);
            tags.push(vec!["t".to_string(), nametag::hash_address_for_tag(pa)]);
        }
    }

    let content_json = serde_json::to_string(&content).expect("binding content serialization");
    Event::create(signer, kinds::APP_DATA, tags, content_json, created_at)
}

/// Filter for `nametag → binding` resolution.
pub fn create_nametag_to_pubkey_filter(nametag_id: &str) -> Filter {
    Filter::builder()
        .kind(kinds::APP_DATA)
        .t_tags([nametag::hash_nametag(nametag_id)])
        .build()
}

/// Filter for `address → binding` reverse lookup.
pub fn create_address_to_binding_filter(address: &str) -> Filter {
    Filter::builder()
        .kind(kinds::APP_DATA)
        .t_tags([nametag::hash_address_for_tag(address)])
        .build()
}

/// Filter for `pubkey → nametags`.
pub fn create_pubkey_to_nametag_filter(nostr_pubkey: &str) -> Filter {
    Filter::builder()
        .kind(kinds::APP_DATA)
        .authors([nostr_pubkey.to_string()])
        .limit(10)
        .build()
}

/// Parse a binding event's content into [`BindingInfo`] (best effort).
pub fn parse_binding_info(event: &Event) -> BindingInfo {
    let ts = event.created_at.saturating_mul(1000);
    let get = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    match serde_json::from_str::<serde_json::Value>(&event.content) {
        Ok(content) => BindingInfo {
            transport_pubkey: event.pubkey.clone(),
            public_key: get(&content, "public_key"),
            l1_address: get(&content, "l1_address"),
            direct_address: get(&content, "direct_address"),
            proxy_address: get(&content, "proxy_address"),
            nametag: get(&content, "nametag"),
            timestamp: ts,
        },
        Err(_) => BindingInfo {
            transport_pubkey: event.pubkey.clone(),
            timestamp: ts,
            ..Default::default()
        },
    }
}

/// Structural + signature validity of a binding event.
pub fn is_valid_binding_event(event: &Event) -> bool {
    if event.kind != kinds::APP_DATA || event.tag_value("d").is_none() {
        return false;
    }
    let ok_content = serde_json::from_str::<serde_json::Value>(&event.content)
        .ok()
        .is_some_and(|c| {
            c.get("nametag_hash")
                .and_then(|x| x.as_str())
                .is_some_and(|s| !s.is_empty())
                && c.get("address")
                    .and_then(|x| x.as_str())
                    .is_some_and(|s| !s.is_empty())
        });
    ok_content && event.verify()
}

/// UNIP-01 owner selection over binding events, including only events for which
/// `include` returns true.
///
/// * Per author, the *latest* (max `created_at`) included event is that author's
///   current binding; `first_seen` is the author's earliest included `created_at`.
/// * If any author's current binding carries the UNIP-01 marker, ownership comes
///   from the marked set: exactly one marked author wins; more than one distinct
///   marked author is ambiguous → `None`. Self-asserted `created_at` is ignored.
/// * Otherwise (legacy) first-seen-wins by `created_at`, lexicographic-pubkey tie-break.
fn resolve_filtered(events: &[Event], include: impl Fn(&Event) -> bool) -> Option<&Event> {
    // author pubkey -> (first_seen, latest_idx, latest_created_at)
    let mut authors: BTreeMap<&str, (i64, usize, i64)> = BTreeMap::new();
    for (i, ev) in events.iter().enumerate() {
        if !include(ev) {
            continue;
        }
        authors
            .entry(ev.pubkey.as_str())
            .and_modify(|e| {
                if ev.created_at < e.0 {
                    e.0 = ev.created_at;
                }
                if ev.created_at > e.2 {
                    e.1 = i;
                    e.2 = ev.created_at;
                }
            })
            .or_insert((ev.created_at, i, ev.created_at));
    }
    if authors.is_empty() {
        return None;
    }

    // UNIP-01 marker preference (read from each author's current/latest event).
    let marked: Vec<usize> = authors
        .values()
        .filter(|(_, idx, _)| nametag::has_ownership_marker(&events[*idx]))
        .map(|(_, idx, _)| *idx)
        .collect();
    if !marked.is_empty() {
        return if marked.len() == 1 {
            Some(&events[marked[0]])
        } else {
            None
        };
    }

    // Legacy: min (first_seen, pubkey).
    let mut winner: Option<(&str, i64, usize)> = None;
    for (pubkey, (first_seen, idx, _)) in &authors {
        let better = match winner {
            None => true,
            Some((wpk, wfirst, _)) => {
                *first_seen < wfirst || (*first_seen == wfirst && *pubkey < wpk)
            }
        };
        if better {
            winner = Some((pubkey, *first_seen, *idx));
        }
    }
    winner.map(|(_, _, idx)| &events[idx])
}

/// Low-level owner selection over a set of binding events. Only signatures are
/// checked, so this trusts the caller to have supplied events that actually match
/// the intended query. **A relay is untrusted** — prefer [`resolve_nametag_owner`]
/// / [`resolve_nametag_pubkey`], which enforce the requested nametag locally.
pub fn resolve_owner(events: &[Event]) -> Option<&Event> {
    resolve_filtered(events, |ev| ev.verify())
}

/// Convenience over [`resolve_owner`].
pub fn resolve_pubkey(events: &[Event]) -> Option<String> {
    resolve_owner(events).map(|e| e.pubkey.clone())
}

/// Resolve the owner of `nametag_id` from relay-returned events, **enforcing the
/// requested identity locally** so a malicious relay cannot inject events that
/// did not match the query (a non-binding event carrying the marker, or a binding
/// for a different nametag). An event is counted only if it is a valid binding
/// event (kind 30078, well-formed content, valid signature) whose `d` tag equals
/// `hash_nametag(nametag_id)`.
pub fn resolve_nametag_owner<'a>(events: &'a [Event], nametag_id: &str) -> Option<&'a Event> {
    let want = nametag::hash_nametag(nametag_id);
    resolve_filtered(events, move |ev| {
        is_valid_binding_event(ev) && ev.tag_value("d") == Some(want.as_str())
    })
}

/// Convenience over [`resolve_nametag_owner`]: the owner's x-only pubkey (hex).
pub fn resolve_nametag_pubkey(events: &[Event], nametag_id: &str) -> Option<String> {
    resolve_nametag_owner(events, nametag_id).map(|e| e.pubkey.clone())
}
