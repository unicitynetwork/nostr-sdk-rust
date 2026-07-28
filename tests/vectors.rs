//! Interop tests: every assertion is against golden vectors generated from the
//! reference TypeScript SDK (`@unicitylabs/nostr-js-sdk` v0.6.0) via
//! `tests/gen-vectors.test.ts` in that repo. Regenerate with:
//!   (cd ../nostr-js-sdk && npx vitest run tests/gen-vectors.test.ts)

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

use unicity_nostr::crypto::{bech32, nip04, nip44, schnorr};
use unicity_nostr::nip17::{self, GiftWrapParams};
use unicity_nostr::{binding, nametag, Event, Filter, Keypair, LocalSigner, Signer};

const VECTORS: &str = include_str!("vectors/nostr-vectors.json");

fn v() -> Value {
    serde_json::from_str(VECTORS).expect("parse vectors")
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn h64(s: &str) -> [u8; 64] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn tags_of(val: &Value) -> Vec<Vec<String>> {
    val.as_array()
        .unwrap()
        .iter()
        .map(|t| {
            t.as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        })
        .collect()
}

#[test]
fn keys_and_bech32() {
    let v = v();
    for who in ["alice", "bob"] {
        let k = &v["keys"][who];
        let kp = Keypair::from_secret_hex(k["priv"].as_str().unwrap()).unwrap();
        assert_eq!(
            kp.public_key_hex(),
            k["xonly_pub"].as_str().unwrap(),
            "{who} xonly"
        );
        assert_eq!(
            kp.npub().unwrap(),
            k["npub"].as_str().unwrap(),
            "{who} npub"
        );
        assert_eq!(
            kp.nsec().unwrap(),
            k["nsec"].as_str().unwrap(),
            "{who} nsec"
        );
        // nsec round-trips back to the same secret
        let from_nsec = Keypair::from_nsec(k["nsec"].as_str().unwrap()).unwrap();
        assert_eq!(
            from_nsec.secret_hex(),
            k["priv"].as_str().unwrap(),
            "{who} nsec roundtrip"
        );
    }
    for b in v["bech32"].as_array().unwrap() {
        let hex_str = b["hex"].as_str().unwrap();
        let encoded = b["encoded"].as_str().unwrap();
        let bytes = h32(hex_str);
        let got = match b["hrp"].as_str().unwrap() {
            "npub" => bech32::encode_npub(&bytes).unwrap(),
            "nsec" => bech32::encode_nsec(&bytes).unwrap(),
            other => panic!("unexpected hrp {other}"),
        };
        assert_eq!(got, encoded);
        // decode round-trip
        let (_, data) = bech32::decode(encoded).unwrap();
        assert_eq!(hex::encode(data), hex_str);
    }
}

#[test]
fn event_ids() {
    let v = v();
    for ev in v["event_ids"].as_array().unwrap() {
        let id = Event::calculate_id(
            ev["pubkey"].as_str().unwrap(),
            ev["created_at"].as_i64().unwrap(),
            ev["kind"].as_u64().unwrap() as u32,
            &tags_of(&ev["tags"]),
            ev["content"].as_str().unwrap(),
        );
        assert_eq!(
            id,
            ev["id"].as_str().unwrap(),
            "content={:?}",
            ev["content"]
        );
    }
}

#[test]
fn schnorr_vectors() {
    let v = v();
    for s in v["schnorr"].as_array().unwrap() {
        let priv_ = h32(s["priv"].as_str().unwrap());
        let msg = h32(s["msg"].as_str().unwrap());
        let pub_ = h32(s["xonly_pub"].as_str().unwrap());
        let sig = h64(s["sig"].as_str().unwrap());

        assert_eq!(
            schnorr::public_key(&priv_).unwrap(),
            pub_,
            "pubkey derivation"
        );
        // aux=0 => deterministic, byte-exact against the reference SDK
        assert_eq!(
            schnorr::sign(&msg, &priv_).unwrap(),
            sig,
            "deterministic signature bytes"
        );
        assert!(
            schnorr::verify(&sig, &msg, &pub_),
            "verify reference signature"
        );
    }
}

#[test]
fn full_event_sign_verify() {
    // End-to-end via the Signer seam: build, sign, verify.
    let v = v();
    let alice =
        LocalSigner::from_secret(h32(v["keys"]["alice"]["priv"].as_str().unwrap())).unwrap();
    let ev = Event::create(
        &alice,
        1,
        vec![vec!["p".into(), "deadbeef".into()]],
        "gm from rust".into(),
        1_700_000_042,
    )
    .unwrap();
    assert!(ev.verify(), "self-signed event must verify");
    assert_eq!(ev.pubkey, hex::encode(alice.public_key()));
    // tamper -> fails
    let mut bad = ev.clone();
    bad.content.push('!');
    assert!(!bad.verify(), "tampered event must not verify");
}

#[test]
fn nip04_vectors() {
    let v = v();
    let ss = &v["nip04"]["shared_secret"];
    let a_priv = h32(ss["a_priv"].as_str().unwrap());
    let b_pub = h32(ss["b_pub"].as_str().unwrap());
    assert_eq!(
        hex::encode(nip04::derive_shared_secret(&a_priv, &b_pub).unwrap()),
        ss["secret"].as_str().unwrap(),
        "nip04 shared secret"
    );

    let bob_priv = h32(v["keys"]["bob"]["priv"].as_str().unwrap());
    for m in v["nip04"]["messages"].as_array().unwrap() {
        let plaintext = m["plaintext"].as_str().unwrap();
        let from_priv = h32(m["from_priv"].as_str().unwrap());
        let from_pub = h32(m["from_pub"].as_str().unwrap());
        let to_pub = h32(m["to_pub"].as_str().unwrap());
        let payload = m["payload"].as_str().unwrap();

        // Recipient (bob) decrypts a message sent by alice.
        let got = nip04::decrypt(&bob_priv, &from_pub, payload).unwrap();
        assert_eq!(got, plaintext, "nip04 decrypt");

        // Byte-exact encrypt for the non-gzip messages, reusing the reference IV.
        if !m["gz"].as_bool().unwrap() {
            let content = payload;
            let (_ct, iv_b64) = content.split_once("?iv=").unwrap();
            let iv: [u8; 16] = STANDARD.decode(iv_b64).unwrap().try_into().unwrap();
            let re = nip04::encrypt_with_iv(&from_priv, &to_pub, plaintext, &iv).unwrap();
            assert_eq!(re, payload, "nip04 byte-exact encrypt");
        }
    }
}

#[test]
fn nip04_roundtrip_gzip() {
    // Our own gzip path (bytes differ from Node's, so round-trip only).
    let v = v();
    let a_priv = h32(v["keys"]["alice"]["priv"].as_str().unwrap());
    let a_pub = h32(v["keys"]["alice"]["xonly_pub"].as_str().unwrap());
    let b_priv = h32(v["keys"]["bob"]["priv"].as_str().unwrap());
    let b_pub = h32(v["keys"]["bob"]["xonly_pub"].as_str().unwrap());
    let big = "z".repeat(5000);
    let iv = [7u8; 16];
    let payload = nip04::encrypt_auto_with_iv(&a_priv, &b_pub, &big, &iv).unwrap();
    assert!(payload.starts_with("gz:"), "large message should compress");
    let got = nip04::decrypt(&b_priv, &a_pub, &payload).unwrap();
    assert_eq!(got, big);
}

#[test]
fn nip44_vectors() {
    let v = v();
    let ck = &v["nip44"]["conversation_key"];
    let a_priv = h32(ck["a_priv"].as_str().unwrap());
    let b_pub = h32(ck["b_pub"].as_str().unwrap());
    let key = nip44::derive_conversation_key(&a_priv, &b_pub).unwrap();
    assert_eq!(
        hex::encode(key),
        ck["key"].as_str().unwrap(),
        "nip44 conversation key"
    );

    // Symmetric: bob's side derives the same key.
    let b_priv = h32(v["keys"]["bob"]["priv"].as_str().unwrap());
    let a_pub = h32(v["keys"]["alice"]["xonly_pub"].as_str().unwrap());
    let key_rev = nip44::derive_conversation_key(&b_priv, &a_pub).unwrap();
    assert_eq!(
        hex::encode(key_rev),
        v["nip44"]["conversation_key_reverse"].as_str().unwrap(),
        "nip44 conversation key symmetry"
    );
    assert_eq!(key, key_rev);

    for m in v["nip44"]["messages"].as_array().unwrap() {
        let plaintext = m["plaintext"].as_str().unwrap();
        let from_priv = h32(m["from_priv"].as_str().unwrap());
        let from_pub = h32(m["from_pub"].as_str().unwrap());
        let to_pub = h32(m["to_pub"].as_str().unwrap());
        let payload = m["payload"].as_str().unwrap();

        // Recipient decrypts.
        let got = nip44::decrypt(&b_priv, &from_pub, payload).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            plaintext,
            "nip44 decrypt: {plaintext:?}"
        );

        // Byte-exact encrypt reusing the reference nonce parsed from the payload.
        let raw = STANDARD.decode(payload).unwrap();
        let nonce: [u8; 24] = raw[1..25].try_into().unwrap();
        let conv = nip44::derive_conversation_key(&from_priv, &to_pub).unwrap();
        let re = nip44::encrypt_with_key_nonce(&conv, &nonce, plaintext.as_bytes()).unwrap();
        assert_eq!(re, payload, "nip44 byte-exact encrypt: {plaintext:?}");
    }
}

#[test]
fn nip17_unwrap_reference_giftwraps() {
    // The crucial interop direction: Rust unwraps a gift wrap produced by the TS SDK
    // (i.e. an AOS agent reads a DM sent by a Sphere wallet).
    let v = v();
    let bob = LocalSigner::from_secret(h32(v["keys"]["bob"]["priv"].as_str().unwrap())).unwrap();
    let alice =
        LocalSigner::from_secret(h32(v["keys"]["alice"]["priv"].as_str().unwrap())).unwrap();

    for m in v["nip17"]["messages"].as_array().unwrap() {
        let gw: Event = serde_json::from_value(m["gift_wrap"].clone()).unwrap();
        let expect = &m["expect"];
        assert_eq!(gw.kind, 1059, "gift wrap kind");

        let pm = nip17::unwrap(&bob, &gw).unwrap();
        assert_eq!(
            pm.content,
            expect["content"].as_str().unwrap(),
            "nip17 content"
        );
        assert_eq!(
            pm.sender_pubkey,
            expect["sender_pub"].as_str().unwrap(),
            "nip17 sender"
        );
        assert_eq!(
            pm.recipient_pubkey,
            expect["recipient_pub"].as_str().unwrap(),
            "nip17 recipient"
        );
        assert_eq!(
            pm.kind,
            expect["kind"].as_u64().unwrap() as u32,
            "nip17 rumor kind"
        );
        if let Some(reply) = expect.get("reply_to").and_then(|r| r.as_str()) {
            assert_eq!(
                pm.reply_to_event_id.as_deref(),
                Some(reply),
                "nip17 reply-to"
            );
        }

        // Wrong recipient (the sender) cannot unwrap.
        assert!(
            nip17::unwrap(&alice, &gw).is_err(),
            "non-recipient must not unwrap"
        );
    }
}

#[test]
fn nip17_roundtrip() {
    // Rust builds a gift wrap and unwraps it; also confirm the sender identity
    // survives (proving the seal signs/encrypts correctly through the Signer seam).
    let v = v();
    let alice =
        LocalSigner::from_secret(h32(v["keys"]["alice"]["priv"].as_str().unwrap())).unwrap();
    let bob = LocalSigner::from_secret(h32(v["keys"]["bob"]["priv"].as_str().unwrap())).unwrap();
    let bob_pub = h32(v["keys"]["bob"]["xonly_pub"].as_str().unwrap());

    let params = GiftWrapParams {
        content: "gm bob, from rust 🦀",
        reply_to: Some("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"),
        rumor_created_at: 1_712_000_000,
        seal_created_at: 1_712_000_123,
        wrap_created_at: 1_711_999_888,
        ephemeral_secret: [9u8; 32],
        seal_nonce: [3u8; 24],
        wrap_nonce: [4u8; 24],
    };
    let gw = nip17::create_gift_wrap(&alice, &bob_pub, &params).unwrap();
    assert_eq!(gw.kind, 1059);
    assert!(
        gw.verify(),
        "gift wrap self-signature (ephemeral key) must verify"
    );

    let pm = nip17::unwrap(&bob, &gw).unwrap();
    assert_eq!(pm.content, "gm bob, from rust 🦀");
    assert_eq!(pm.sender_pubkey, alice.keypair().public_key_hex());
    assert_eq!(pm.reply_to_event_id.as_deref(), params.reply_to);
    assert_eq!(pm.kind, 14);
}

#[test]
fn nametag_vectors() {
    let v = v();
    let nt = &v["nametag"];

    for s in nt["sha256_hex"].as_array().unwrap() {
        assert_eq!(
            nametag::sha256_hex(s["input"].as_str().unwrap()),
            s["hex"].as_str().unwrap()
        );
    }
    for m in nt["hash_nametag"].as_array().unwrap() {
        assert_eq!(
            nametag::hash_nametag(m["nametag"].as_str().unwrap()),
            m["hash"].as_str().unwrap(),
            "hash_nametag {:?}",
            m["nametag"]
        );
    }
    for m in nt["hash_address"].as_array().unwrap() {
        assert_eq!(
            nametag::hash_address_for_tag(m["address"].as_str().unwrap()),
            m["hash"].as_str().unwrap()
        );
    }
    for m in nt["valid"].as_array().unwrap() {
        assert_eq!(
            nametag::is_valid_nametag(m["nametag"].as_str().unwrap()),
            m["valid"].as_bool().unwrap(),
            "is_valid_nametag {:?}",
            m["nametag"]
        );
    }
    // encrypted_nametag: decrypt the reference output, then byte-exact re-encrypt
    // reusing the reference IV.
    for m in nt["encrypt"].as_array().unwrap() {
        let name = m["nametag"].as_str().unwrap();
        let priv_ = h32(m["priv"].as_str().unwrap());
        let payload = m["payload"].as_str().unwrap();
        assert_eq!(
            nametag::decrypt_nametag(payload, &priv_).unwrap(),
            name,
            "nametag decrypt"
        );
        let raw = STANDARD.decode(payload).unwrap();
        let iv: [u8; 12] = raw[..12].try_into().unwrap();
        let re = nametag::encrypt_nametag_with_iv(name, &priv_, &iv).unwrap();
        assert_eq!(re, payload, "nametag byte-exact encrypt: {name:?}");
    }
}

#[test]
fn unip01_ownership_marker() {
    let alice = LocalSigner::from_secret([5u8; 32]).unwrap();
    let marked = Event::create(
        &alice,
        30078,
        vec![
            vec!["d".into(), nametag::hash_nametag("alice")],
            vec!["L".into(), "unicity:nametag".into()],
        ],
        "{}".into(),
        1_700_000_000,
    )
    .unwrap();
    assert!(nametag::has_ownership_marker(&marked));

    let unmarked = Event::create(
        &alice,
        30078,
        vec![vec!["d".into(), "x".into()]],
        "{}".into(),
        1,
    )
    .unwrap();
    assert!(!nametag::has_ownership_marker(&unmarked));
}

fn binding_event(v: &Value, desc: &str) -> Event {
    let e = v["binding"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["desc"] == desc)
        .unwrap();
    serde_json::from_value(e["event"].clone()).unwrap()
}

#[test]
fn filter_shapes() {
    let v = v();
    for f in v["binding"]["filters"].as_array().unwrap() {
        let input = f["input"].as_str().unwrap();
        let filter = match f["kind"].as_str().unwrap() {
            "nametag" => binding::create_nametag_to_pubkey_filter(input),
            "address" => binding::create_address_to_binding_filter(input),
            "pubkey" => binding::create_pubkey_to_nametag_filter(input),
            other => panic!("unexpected filter kind {other}"),
        };
        let got: Value = serde_json::from_str(&filter.to_json()).unwrap();
        assert_eq!(got, f["json"], "filter {:?}", f["kind"]);
    }
}

#[test]
fn binding_events_verify() {
    let v = v();
    for e in v["binding"]["events"].as_array().unwrap() {
        let ev: Event = serde_json::from_value(e["event"].clone()).unwrap();
        assert!(ev.verify(), "binding event verifies: {:?}", e["desc"]);
        assert!(
            binding::is_valid_binding_event(&ev),
            "is_valid_binding_event"
        );
        assert!(nametag::has_ownership_marker(&ev), "marker present");
        assert_eq!(ev.pubkey, e["author_pub"].as_str().unwrap());
        assert_eq!(
            ev.tag_value("d").unwrap(),
            nametag::hash_nametag(e["nametag"].as_str().unwrap()),
            "d-tag == hashed nametag"
        );
    }
}

#[test]
fn unip01_resolution() {
    let v = v();
    let alice_shared = binding_event(&v, "alice-shared");
    let bob_shared = binding_event(&v, "bob-shared");
    let alice_only = binding_event(&v, "alice-only");
    let alice_pub = v["keys"]["alice"]["xonly_pub"].as_str().unwrap();

    // Single marked owner resolves to that author.
    assert_eq!(
        binding::resolve_pubkey(core::slice::from_ref(&alice_only)).as_deref(),
        Some(alice_pub)
    );

    // Two distinct marked owners for the same nametag => ambiguous => None.
    assert!(
        binding::resolve_owner(&[alice_shared.clone(), bob_shared.clone()]).is_none(),
        "two marked owners must be ambiguous"
    );

    // Bad-signature events are skipped: tampering bob's binding leaves alice the
    // sole valid marked owner.
    let mut bob_bad = bob_shared.clone();
    bob_bad.content.push('X');
    assert!(!bob_bad.verify());
    assert_eq!(
        binding::resolve_pubkey(&[alice_shared, bob_bad]).as_deref(),
        Some(alice_pub),
        "forged event skipped"
    );
}

#[test]
fn resolution_legacy_first_seen_wins() {
    // Legacy (unmarked) path: earliest created_at wins, lexicographic-pubkey tie-break.
    let a = LocalSigner::from_secret([1u8; 32]).unwrap();
    let b = LocalSigner::from_secret([2u8; 32]).unwrap();
    let content = r#"{"nametag_hash":"n","address":"x"}"#;
    let mk = |s: &LocalSigner, created: i64| {
        Event::create(
            s,
            30078,
            vec![vec!["d".into(), "n".into()]],
            content.into(),
            created,
        )
        .unwrap()
    };

    let a_old = mk(&a, 100);
    let b_new = mk(&b, 200);
    assert_eq!(
        binding::resolve_pubkey(&[b_new, a_old]).as_deref(),
        Some(a.keypair().public_key_hex().as_str()),
        "earlier created_at wins"
    );

    // Tie on created_at => lexicographically smaller pubkey.
    let a_pk = a.keypair().public_key_hex();
    let b_pk = b.keypair().public_key_hex();
    let expected = core::cmp::min(a_pk.clone(), b_pk.clone());
    assert_eq!(
        binding::resolve_pubkey(&[mk(&a, 150), mk(&b, 150)]),
        Some(expected),
        "tie-break by smaller pubkey"
    );
}

#[test]
fn resolution_rejects_relay_injection() {
    // Hardening (Codex P1): resolve_nametag_* enforces the requested nametag +
    // binding structure locally, so a malicious relay cannot inject events that
    // did not match the query.
    let alice = LocalSigner::from_secret([1u8; 32]).unwrap();
    let attacker = LocalSigner::from_secret([2u8; 32]).unwrap();

    // Legit marked binding for "target" owned by alice.
    let legit =
        binding::create_binding_event(&alice, "target", "DIRECT://a", 10, 10, None, None).unwrap();
    // Injection 1: attacker-signed kind-1 note (NOT a binding) carrying the marker
    // and the target's d-tag.
    let inj_note = Event::create(
        &attacker,
        1,
        vec![
            vec!["L".into(), "unicity:nametag".into()],
            vec!["d".into(), nametag::hash_nametag("target")],
        ],
        "{}".into(),
        20,
    )
    .unwrap();
    // Injection 2: attacker's valid marked binding for a DIFFERENT nametag.
    let inj_other =
        binding::create_binding_event(&attacker, "other", "DIRECT://x", 5, 5, None, None).unwrap();

    let events = vec![legit, inj_note, inj_other];
    // Safe resolution ignores both injections => alice owns "target".
    assert_eq!(
        binding::resolve_nametag_pubkey(&events, "target").as_deref(),
        Some(alice.keypair().public_key_hex().as_str()),
        "injected non-matching events must be ignored"
    );

    // Attacker-only injection cannot hijack an unclaimed nametag.
    let attacker_note = Event::create(
        &attacker,
        1,
        vec![
            vec!["L".into(), "unicity:nametag".into()],
            vec!["d".into(), nametag::hash_nametag("victim")],
        ],
        "{}".into(),
        1,
    )
    .unwrap();
    assert!(
        binding::resolve_nametag_owner(core::slice::from_ref(&attacker_note), "victim").is_none(),
        "a non-binding marked event must not win a nametag"
    );
}

#[test]
fn filter_matches() {
    // Codex P2: ids/authors match as NIP-01 prefixes; plus kind/since/until/tags.
    let alice = LocalSigner::from_secret([1u8; 32]).unwrap();
    let ev = Event::create(
        &alice,
        1,
        vec![vec!["t".into(), "topic".into()]],
        "hi".into(),
        100,
    )
    .unwrap();
    let pk = alice.keypair().public_key_hex();

    assert!(
        Filter::builder().authors([pk.clone()]).build().matches(&ev),
        "full author"
    );
    assert!(
        Filter::builder()
            .authors([pk[..8].to_string()])
            .build()
            .matches(&ev),
        "author prefix"
    );
    assert!(
        !Filter::builder()
            .authors(["ffffffff".to_string()])
            .build()
            .matches(&ev),
        "wrong author prefix"
    );
    assert!(
        Filter::builder()
            .ids([ev.id[..6].to_string()])
            .build()
            .matches(&ev),
        "id prefix"
    );
    assert!(Filter::builder()
        .kind(1)
        .since(100)
        .until(100)
        .t_tags(["topic".to_string()])
        .build()
        .matches(&ev));
    assert!(
        !Filter::builder().kind(2).build().matches(&ev),
        "wrong kind"
    );
    assert!(
        !Filter::builder().since(101).build().matches(&ev),
        "since after"
    );
    assert!(
        !Filter::builder()
            .t_tags(["nope".to_string()])
            .build()
            .matches(&ev),
        "wrong tag"
    );
}
