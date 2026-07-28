//! Interop tests: every assertion is against golden vectors generated from the
//! reference TypeScript SDK (`@unicitylabs/nostr-js-sdk` v0.6.0) via
//! `tests/gen-vectors.test.ts` in that repo. Regenerate with:
//!   (cd ../nostr-js-sdk && npx vitest run tests/gen-vectors.test.ts)

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

use unicity_nostr::crypto::{bech32, nip04, nip44, schnorr};
use unicity_nostr::{Event, Keypair, LocalSigner, Signer};

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
