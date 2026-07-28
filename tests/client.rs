//! Network-free tests for the relay client + multi-relay client, using a mock
//! `RelayConnection` that auto-responds (OK for EVENT, served events + EOSE for REQ).

use std::collections::VecDeque;
use std::time::Duration;

use serde_json::Value;
use unicity_nostr::client::multi::MultiRelayClient;
use unicity_nostr::client::{RelayClient, RelayConnection};
use unicity_nostr::{Event, Filter, LocalSigner};

/// A scripted relay: replies `OK` to any EVENT, and serves `events` + EOSE for any REQ.
struct MockConnection {
    events: Vec<Event>,
    out: VecDeque<String>,
}

impl MockConnection {
    fn new(events: Vec<Event>) -> Self {
        Self {
            events,
            out: VecDeque::new(),
        }
    }
}

impl RelayConnection for MockConnection {
    fn send(&mut self, text: &str) -> unicity_nostr::Result<()> {
        let v: Vec<Value> = serde_json::from_str(text).unwrap();
        match v[0].as_str().unwrap() {
            "EVENT" => {
                let id = v[1]["id"].as_str().unwrap();
                self.out.push_back(format!(r#"["OK","{id}",true,""]"#));
            }
            "REQ" => {
                let sub = v[1].as_str().unwrap();
                for ev in &self.events {
                    self.out.push_back(format!(
                        "[\"EVENT\",\"{sub}\",{}]",
                        serde_json::to_string(ev).unwrap()
                    ));
                }
                self.out.push_back(format!(r#"["EOSE","{sub}"]"#));
            }
            _ => {}
        }
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> unicity_nostr::Result<Option<String>> {
        Ok(self.out.pop_front())
    }

    fn close(&mut self) {}
}

fn note(signer: &LocalSigner, content: &str, ts: i64) -> Event {
    Event::create(signer, 1, vec![], content.into(), ts).unwrap()
}

#[test]
fn single_relay_publish_and_query() {
    let alice = LocalSigner::from_secret([1u8; 32]).unwrap();
    let e1 = note(&alice, "one", 1);
    let e2 = note(&alice, "two", 2);
    let conn = MockConnection::new(vec![e1.clone(), e2.clone()]);
    let mut client = RelayClient::new(conn, "wss://mock", &alice, || 0);

    let (accepted, _) = client.publish(&e1, Duration::from_secs(1)).unwrap();
    assert!(accepted, "mock relay accepts the event");

    let got = client
        .query(
            &Filter::builder().kinds([1u32]).build(),
            Duration::from_millis(50),
        )
        .unwrap();
    assert_eq!(got.len(), 2, "both served events collected until EOSE");
    assert!(got.iter().any(|e| e.content == "one"));
    assert!(got.iter().any(|e| e.content == "two"));
}

#[test]
fn persistent_subscribe_poll() {
    let alice = LocalSigner::from_secret([1u8; 32]).unwrap();
    let e1 = note(&alice, "live", 1);
    let conn = MockConnection::new(vec![e1.clone()]);
    let mut client = RelayClient::new(conn, "wss://mock", &alice, || 0);

    client
        .subscribe("s1", &Filter::builder().kinds([1u32]).build())
        .unwrap();
    let got = client.poll_event(Duration::from_millis(50)).unwrap();
    let (sub, ev) = got.expect("one live event");
    assert_eq!(sub, "s1");
    assert_eq!(ev.content, "live");
}

#[test]
fn multi_relay_broadcast_and_dedup() {
    let alice = LocalSigner::from_secret([1u8; 32]).unwrap();
    let e1 = note(&alice, "one", 1);
    let e2 = note(&alice, "two", 2);
    let e3 = note(&alice, "three", 3);

    // Relay A serves {e1, e2}; relay B serves {e2, e3} (e2 overlaps).
    let a = RelayClient::new(
        MockConnection::new(vec![e1.clone(), e2.clone()]),
        "wss://a",
        &alice,
        || 0,
    );
    let b = RelayClient::new(
        MockConnection::new(vec![e2.clone(), e3.clone()]),
        "wss://b",
        &alice,
        || 0,
    );
    let mut multi = MultiRelayClient::from_clients(vec![a, b]);
    assert_eq!(multi.relay_count(), 2);

    let outcomes = multi.broadcast(&e1, Duration::from_secs(1));
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes.iter().all(|o| matches!(o.result, Ok((true, _)))),
        "both relays accept"
    );

    let events = multi.query(
        &Filter::builder().kinds([1u32]).build(),
        Duration::from_millis(50),
    );
    assert_eq!(events.len(), 3, "union deduplicated by id: e1, e2, e3");
}
