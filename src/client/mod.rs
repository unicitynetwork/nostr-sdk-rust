//! A minimal single-relay Nostr client: relay-message parsing, a transport
//! abstraction, and a [`RelayClient`] that can publish, subscribe/query, and
//! answer NIP-42 AUTH challenges.
//!
//! The client is **transport-agnostic** — it drives a [`RelayConnection`] the
//! caller supplies. The capsule will implement that over the Astrid `net`
//! interface (rustls + tungstenite); the `native-transport` feature provides a
//! std/tungstenite implementation for host tools and the e2e tests.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::event::Event;
use crate::filter::Filter;
use crate::kinds;
use crate::signer::Signer;

#[cfg(feature = "native-transport")]
pub mod native;

/// A message received from a relay (NIP-01 + NIP-42).
#[derive(Clone, Debug)]
pub enum RelayMessage {
    /// `["EVENT", sub_id, event]`
    Event {
        /// Subscription id the event belongs to.
        sub_id: String,
        /// The event.
        event: Box<Event>,
    },
    /// `["EOSE", sub_id]` — end of stored events.
    Eose {
        /// Subscription id.
        sub_id: String,
    },
    /// `["OK", event_id, accepted, message]` — publish acknowledgement.
    Ok {
        /// Event id acknowledged.
        id: String,
        /// Whether the relay accepted the event.
        accepted: bool,
        /// Human-readable message.
        message: String,
    },
    /// `["CLOSED", sub_id, message]` — subscription closed by the relay.
    Closed {
        /// Subscription id.
        sub_id: String,
        /// Reason.
        message: String,
    },
    /// `["NOTICE", message]`
    Notice {
        /// Notice text.
        message: String,
    },
    /// `["AUTH", challenge]` — NIP-42 authentication challenge.
    Auth {
        /// Challenge string.
        challenge: String,
    },
    /// Anything unrecognized (kept as the raw first element / text).
    Other(String),
}

/// Parse a relay wire frame. Unrecognized or malformed frames map to
/// [`RelayMessage::Other`] rather than erroring, so a stray frame never aborts a
/// read loop.
pub fn parse_relay_message(text: &str) -> RelayMessage {
    let arr: Vec<Value> = match serde_json::from_str(text) {
        Ok(a) => a,
        Err(_) => return RelayMessage::Other(text.to_string()),
    };
    let typ = arr.first().and_then(Value::as_str).unwrap_or("");
    let s = |i: usize| arr.get(i).and_then(Value::as_str).unwrap_or("").to_string();
    match typ {
        "EVENT" => match arr.get(2).cloned().map(serde_json::from_value::<Event>) {
            Some(Ok(event)) => RelayMessage::Event {
                sub_id: s(1),
                event: Box::new(event),
            },
            _ => RelayMessage::Other(text.to_string()),
        },
        "EOSE" => RelayMessage::Eose { sub_id: s(1) },
        "OK" => RelayMessage::Ok {
            id: s(1),
            accepted: arr.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: s(3),
        },
        "CLOSED" => RelayMessage::Closed {
            sub_id: s(1),
            message: s(2),
        },
        "NOTICE" => RelayMessage::Notice { message: s(1) },
        "AUTH" => RelayMessage::Auth { challenge: s(1) },
        other => RelayMessage::Other(other.to_string()),
    }
}

/// A single relay connection: send a text frame, receive one (with a timeout),
/// and close. `recv` returns `Ok(None)` on timeout and `Err` on a closed/broken
/// connection.
pub trait RelayConnection {
    /// Send a text frame.
    fn send(&mut self, text: &str) -> Result<()>;
    /// Receive the next text frame, or `None` if `timeout` elapses first.
    fn recv(&mut self, timeout: Duration) -> Result<Option<String>>;
    /// Close the connection.
    fn close(&mut self);
}

/// Opens [`RelayConnection`]s to relay URLs.
pub trait Transport {
    /// The connection type produced.
    type Conn: RelayConnection;
    /// Connect to `url` (e.g. `wss://relay.example`).
    fn connect(&self, url: &str) -> Result<Self::Conn>;
}

/// A single-relay client bound to a connection and a signer (for NIP-42 AUTH).
/// `now` supplies the current unix time (seconds) for AUTH events — the host
/// clock in the capsule, `SystemTime` on native.
pub struct RelayClient<'s, C: RelayConnection, S: Signer> {
    conn: C,
    url: String,
    signer: &'s S,
    now: fn() -> i64,
}

impl<'s, C: RelayConnection, S: Signer> RelayClient<'s, C, S> {
    /// Wrap a connection.
    pub fn new(conn: C, url: impl Into<String>, signer: &'s S, now: fn() -> i64) -> Self {
        Self {
            conn,
            url: url.into(),
            signer,
            now,
        }
    }

    fn send_frame(&mut self, frame: Value) -> Result<()> {
        self.conn.send(&frame.to_string())
    }

    fn send_req(&mut self, sub_id: &str, filter: &Filter) -> Result<()> {
        let filter_val = serde_json::to_value(filter)
            .map_err(|e| Error::Decode(alloc::format!("filter: {e}")))?;
        self.send_frame(Value::Array(vec![
            Value::from("REQ"),
            Value::from(sub_id),
            filter_val,
        ]))
    }

    fn send_close(&mut self, sub_id: &str) -> Result<()> {
        self.send_frame(Value::Array(vec![
            Value::from("CLOSE"),
            Value::from(sub_id),
        ]))
    }

    fn answer_auth(&mut self, challenge: &str) -> Result<()> {
        let auth = Event::create(
            self.signer,
            kinds::AUTH,
            vec![
                vec!["relay".to_string(), self.url.clone()],
                vec!["challenge".to_string(), challenge.to_string()],
            ],
            String::new(),
            (self.now)(),
        )?;
        let ev =
            serde_json::to_value(&auth).map_err(|e| Error::Decode(alloc::format!("auth: {e}")))?;
        self.send_frame(Value::Array(vec![Value::from("AUTH"), ev]))
    }

    /// Receive one message, transparently answering an AUTH challenge (the
    /// `Auth` message is still returned so callers can re-subscribe).
    fn recv_msg(&mut self, timeout: Duration) -> Result<Option<RelayMessage>> {
        match self.conn.recv(timeout)? {
            None => Ok(None),
            Some(text) => {
                let msg = parse_relay_message(&text);
                if let RelayMessage::Auth { challenge } = &msg {
                    self.answer_auth(challenge)?;
                }
                Ok(Some(msg))
            }
        }
    }

    /// Publish an event and wait for its `OK`. Answers an AUTH challenge and
    /// re-sends once if the relay demands auth first.
    pub fn publish(&mut self, event: &Event, timeout: Duration) -> Result<(bool, String)> {
        let ev =
            serde_json::to_value(event).map_err(|e| Error::Decode(alloc::format!("event: {e}")))?;
        let frame = Value::Array(vec![Value::from("EVENT"), ev]);
        self.send_frame(frame.clone())?;

        let mut resent = false;
        for _ in 0..64 {
            match self.recv_msg(timeout)? {
                Some(RelayMessage::Ok {
                    id,
                    accepted,
                    message,
                }) if id == event.id => {
                    return Ok((accepted, message));
                }
                Some(RelayMessage::Auth { .. }) if !resent => {
                    // Auth answered inside recv_msg; re-send the event once.
                    resent = true;
                    self.send_frame(frame.clone())?;
                }
                None => return Err(Error::Malformed("publish: timed out waiting for OK")),
                _ => continue,
            }
        }
        Err(Error::Malformed("publish: no OK received"))
    }

    /// Subscribe and collect stored events until EOSE/CLOSED, or until no frame
    /// arrives within `idle`. Signature-invalid events are skipped. Answers AUTH
    /// and re-subscribes if challenged mid-query.
    pub fn query(&mut self, filter: &Filter, idle: Duration) -> Result<Vec<Event>> {
        let sub_id = "q0";
        self.send_req(sub_id, filter)?;
        let mut events = Vec::new();
        loop {
            match self.recv_msg(idle)? {
                Some(RelayMessage::Event { sub_id: s, event }) if s == sub_id => {
                    if event.verify() {
                        events.push(*event);
                    }
                }
                Some(RelayMessage::Eose { sub_id: s }) if s == sub_id => break,
                Some(RelayMessage::Closed { sub_id: s, .. }) if s == sub_id => break,
                Some(RelayMessage::Auth { .. }) => {
                    // Re-arm the subscription after authenticating.
                    self.send_req(sub_id, filter)?;
                }
                None => break, // idle timeout — assume the relay is done
                _ => continue,
            }
        }
        let _ = self.send_close(sub_id);
        Ok(events)
    }

    /// Close the underlying connection.
    pub fn close(mut self) {
        self.conn.close();
    }
}
