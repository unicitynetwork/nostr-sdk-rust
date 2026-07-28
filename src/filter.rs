//! NIP-01 subscription filter, a port of `nostr-js-sdk/src/protocol/Filter.ts`.
//! Serializes to the relay wire shape (`#e`/`#p`/`#t`/`#d`/`#h` tag filters),
//! omitting empty fields. Also provides local [`Filter::matches`] for testing
//! and in-capsule filtering.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::event::Event;

fn is_empty<T>(o: &Option<Vec<T>>) -> bool {
    o.as_ref().is_none_or(|v| v.is_empty())
}

/// A Nostr subscription filter. Absent (`None`/empty) fields impose no constraint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Event ids to match.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub ids: Option<Vec<String>>,
    /// Author x-only pubkeys (hex) to match.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub authors: Option<Vec<String>>,
    /// Event kinds to match.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub kinds: Option<Vec<u32>>,
    /// `e` tag values to match.
    #[serde(rename = "#e", default, skip_serializing_if = "is_empty")]
    pub e_tags: Option<Vec<String>>,
    /// `p` tag values to match.
    #[serde(rename = "#p", default, skip_serializing_if = "is_empty")]
    pub p_tags: Option<Vec<String>>,
    /// `t` tag values to match.
    #[serde(rename = "#t", default, skip_serializing_if = "is_empty")]
    pub t_tags: Option<Vec<String>>,
    /// `d` tag values to match.
    #[serde(rename = "#d", default, skip_serializing_if = "is_empty")]
    pub d_tags: Option<Vec<String>>,
    /// `h` tag values to match (NIP-29 group ids).
    #[serde(rename = "#h", default, skip_serializing_if = "is_empty")]
    pub h_tags: Option<Vec<String>>,
    /// Minimum `created_at` (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    /// Maximum `created_at` (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Maximum number of events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl Filter {
    /// A new empty filter builder.
    pub fn builder() -> FilterBuilder {
        FilterBuilder::default()
    }

    /// Serialize to the compact relay JSON form (empty fields omitted).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("filter serialization is infallible")
    }

    /// Does `event` satisfy every constraint in this filter?
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ids) = &self.ids {
            if !ids.iter().any(|i| i == &event.id) {
                return false;
            }
        }
        if let Some(authors) = &self.authors {
            if !authors.iter().any(|a| a == &event.pubkey) {
                return false;
            }
        }
        if let Some(kinds) = &self.kinds {
            if !kinds.contains(&event.kind) {
                return false;
            }
        }
        if !self.tag_matches("e", &self.e_tags, event)
            || !self.tag_matches("p", &self.p_tags, event)
            || !self.tag_matches("t", &self.t_tags, event)
            || !self.tag_matches("d", &self.d_tags, event)
            || !self.tag_matches("h", &self.h_tags, event)
        {
            return false;
        }
        if let Some(since) = self.since {
            if event.created_at < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if event.created_at > until {
                return false;
            }
        }
        true
    }

    fn tag_matches(&self, name: &str, wanted: &Option<Vec<String>>, event: &Event) -> bool {
        match wanted {
            None => true,
            Some(vals) if vals.is_empty() => true,
            Some(vals) => event.tags.iter().any(|t| {
                t.first().map(String::as_str) == Some(name)
                    && t.get(1).is_some_and(|v| vals.contains(v))
            }),
        }
    }
}

/// Chained builder for [`Filter`].
#[derive(Default)]
pub struct FilterBuilder {
    f: Filter,
}

macro_rules! vec_setter {
    ($name:ident, $field:ident, $t:ty) => {
        /// Set the field.
        pub fn $name(mut self, values: impl IntoIterator<Item = $t>) -> Self {
            self.f.$field = Some(values.into_iter().collect());
            self
        }
    };
}

impl FilterBuilder {
    vec_setter!(ids, ids, String);
    vec_setter!(authors, authors, String);
    vec_setter!(kinds, kinds, u32);
    vec_setter!(e_tags, e_tags, String);
    vec_setter!(p_tags, p_tags, String);
    vec_setter!(t_tags, t_tags, String);
    vec_setter!(d_tags, d_tags, String);
    vec_setter!(h_tags, h_tags, String);

    /// Convenience for a single kind.
    pub fn kind(mut self, kind: u32) -> Self {
        self.f.kinds = Some(vec![kind]);
        self
    }

    /// Set `since`.
    pub fn since(mut self, since: i64) -> Self {
        self.f.since = Some(since);
        self
    }

    /// Set `until`.
    pub fn until(mut self, until: i64) -> Self {
        self.f.until = Some(until);
        self
    }

    /// Set `limit`.
    pub fn limit(mut self, limit: u32) -> Self {
        self.f.limit = Some(limit);
        self
    }

    /// Finish building.
    pub fn build(self) -> Filter {
        self.f
    }
}
