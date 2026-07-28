//! A multi-relay client: broadcast a publish to several relays and merge query
//! results (deduplicated by event id). It composes single-relay [`RelayClient`]s,
//! so it stays transport-agnostic.
//!
//! I/O is sequential (one relay after another). For a handful of relays that is
//! fine; a fully concurrent implementation would need non-blocking multiplexing,
//! which the caller's transport can add later. Reconnect supervision is likewise
//! left to the caller (re-`connect` a relay via the [`Transport`]).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::client::{RelayClient, RelayConnection, Transport};
use crate::error::Result;
use crate::event::Event;
use crate::filter::Filter;
use crate::signer::Signer;

/// Per-relay result of a broadcast publish.
#[derive(Clone, Debug)]
pub struct PublishOutcome {
    /// Relay URL.
    pub url: String,
    /// The relay's `OK` acceptance, or `Err` details as a string.
    pub result: core::result::Result<(bool, String), String>,
}

/// A client fanning out over several relays.
pub struct MultiRelayClient<'s, C: RelayConnection, S: Signer> {
    clients: Vec<RelayClient<'s, C, S>>,
}

impl<'s, C: RelayConnection, S: Signer> MultiRelayClient<'s, C, S> {
    /// Connect to every `url` with `transport`. A relay that fails to connect is
    /// skipped and reported in the returned `errors` list (by url + message).
    pub fn connect<T: Transport<Conn = C>>(
        transport: &T,
        urls: &[&str],
        signer: &'s S,
        now: fn() -> i64,
    ) -> (Self, Vec<(String, String)>) {
        let mut clients = Vec::new();
        let mut errors = Vec::new();
        for url in urls {
            match transport.connect(url) {
                Ok(conn) => clients.push(RelayClient::new(conn, *url, signer, now)),
                Err(e) => errors.push((String::from(*url), alloc::format!("{e}"))),
            }
        }
        (Self { clients }, errors)
    }

    /// Wrap already-connected clients.
    pub fn from_clients(clients: Vec<RelayClient<'s, C, S>>) -> Self {
        Self { clients }
    }

    /// Number of connected relays.
    pub fn relay_count(&self) -> usize {
        self.clients.len()
    }

    /// Publish `event` to every relay; returns each relay's outcome.
    pub fn broadcast(&mut self, event: &Event, timeout: Duration) -> Vec<PublishOutcome> {
        self.clients
            .iter_mut()
            .map(|c| PublishOutcome {
                url: String::from(c.url()),
                result: c.publish(event, timeout).map_err(|e| alloc::format!("{e}")),
            })
            .collect()
    }

    /// Query every relay and return the union of events, deduplicated by id
    /// (first occurrence wins). A relay that errors is skipped.
    pub fn query(&mut self, filter: &Filter, idle: Duration) -> Vec<Event> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for c in &mut self.clients {
            if let Ok(events) = c.query(filter, idle) {
                for ev in events {
                    if seen.insert(ev.id.clone()) {
                        out.push(ev);
                    }
                }
            }
        }
        out
    }

    /// Open the same subscription on every relay (for a persistent listener).
    pub fn subscribe(&mut self, sub_id: &str, filter: &Filter) -> Result<()> {
        for c in &mut self.clients {
            c.subscribe(sub_id, filter)?;
        }
        Ok(())
    }

    /// Access the underlying per-relay clients (e.g. to `poll` them in a loop).
    pub fn clients_mut(&mut self) -> &mut [RelayClient<'s, C, S>] {
        &mut self.clients
    }

    /// Close every connection.
    pub fn close(self) {
        for c in self.clients {
            c.close();
        }
    }
}
