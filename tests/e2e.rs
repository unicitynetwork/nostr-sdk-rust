//! End-to-end tests against a **deployed** Unicity relay. These hit the network,
//! so they are `#[ignore]` by default and require the `native-transport` feature:
//!
//!   cargo test --features native-transport --test e2e -- --ignored --nocapture
//!
//! `e2e_publish_and_read_dm` is the real proof: a fresh identity sends a
//! NIP-17 gift-wrapped DM to itself through the live relay and reads it back
//! decrypted — exercising connect, NIP-42 AUTH (if demanded), publish, subscribe,
//! and unwrap end to end.
#![cfg(feature = "native-transport")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use unicity_nostr::client::native::NativeTransport;
use unicity_nostr::client::{RelayClient, Transport};
use unicity_nostr::{nip17, Filter, GiftWrapParams, LocalSigner, Signer};

const RELAY: &str = "wss://nostr-relay.testnet.unicity.network";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap();
    b
}

#[test]
#[ignore = "network: connects to a live relay"]
fn e2e_connect_and_eose() {
    let signer = LocalSigner::from_secret(rand_bytes::<32>()).unwrap();
    let conn = NativeTransport.connect(RELAY).expect("connect to relay");
    let mut client = RelayClient::new(conn, RELAY, &signer, now);

    // A cheap query just to prove REQ -> (events) -> EOSE round-trips.
    let filter = Filter::builder().kinds([0u32]).limit(1).build();
    let events = client
        .query(&filter, Duration::from_secs(6))
        .expect("query");
    eprintln!("[e2e] connect+EOSE ok; received {} event(s)", events.len());
    client.close();
}

#[test]
#[ignore = "network: connects to a live relay"]
fn e2e_publish_and_read_dm() {
    let signer = LocalSigner::from_secret(rand_bytes::<32>()).unwrap();
    let me = signer.public_key();
    let me_hex = hex::encode(me);
    let content = format!("e2e rust dm {}", now());

    let conn = NativeTransport.connect(RELAY).expect("connect to relay");
    let mut client = RelayClient::new(conn, RELAY, &signer, now);

    // Build a self-addressed gift wrap.
    let params = GiftWrapParams {
        content: &content,
        reply_to: None,
        rumor_created_at: now(),
        seal_created_at: now(),
        wrap_created_at: now(),
        ephemeral_secret: rand_bytes::<32>(),
        seal_nonce: rand_bytes::<24>(),
        wrap_nonce: rand_bytes::<24>(),
    };
    let gw = nip17::create_gift_wrap(&signer, &me, &params).expect("gift wrap");
    eprintln!("[e2e] publishing gift wrap {}", gw.id);

    let (accepted, msg) = client
        .publish(&gw, Duration::from_secs(10))
        .expect("publish");
    eprintln!("[e2e] publish -> accepted={accepted} msg={msg:?}");
    assert!(accepted, "relay rejected the gift wrap: {msg}");

    // Read it back: kind 1059 addressed to us.
    let filter = Filter::builder()
        .kinds([1059u32])
        .p_tags([me_hex.clone()])
        .since(now() - 300)
        .build();
    let events = client
        .query(&filter, Duration::from_secs(8))
        .expect("query");
    eprintln!("[e2e] read back {} gift wrap(s)", events.len());

    let found = events.iter().any(|ev| {
        matches!(nip17::unwrap(&signer, ev), Ok(pm)
            if pm.content == content && pm.sender_pubkey == me_hex)
    });
    assert!(found, "did not read back our own DM (content={content:?})");
    eprintln!("[e2e] round-trip DM verified through the live relay");
    client.close();
}
