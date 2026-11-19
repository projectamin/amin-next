//! Session-scoped server state — the Rust form of `Amin::AXA::Store`.
//!
//! State lives behind the store (axa-plan §4.7): `get`/`set`/`delete` keyed by
//! session id, plus [`Store::update`] for a read-modify-write that must not be
//! lost when two callers interleave.  This is the in-memory adapter; a prefork
//! server hands in a durable one (`Amin::AXA::Store::SQLite`) that implements
//! the same methods.  It is process-scoped by design — the one piece of mutable
//! state §4.9 allows at process lifetime, because it is keyed by session and
//! never shared across sessions.
//!
//! A record is a CSRF token and a cart: `{ csrf => …, cart => { sku => qty } }`.
//! The cart is a [`BTreeMap`] so page rows come out in sorted sku order without
//! a separate sort — the Perl adapter sorts with `sort keys %$cart`.

use std::collections::BTreeMap;
use std::collections::HashMap;

/// A session record: the CSRF token minted with the session and its cart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// The CSRF token the session's mutations must present.
    pub csrf: String,
    /// Cart contents, sku → quantity (sorted, so page order is deterministic).
    pub cart: BTreeMap<String, u64>,
}

/// An in-memory, session-keyed store (≈ `Amin::AXA::Store`).
#[derive(Debug, Default)]
pub struct Store {
    data: HashMap<String, Record>,
}

impl Store {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The record keyed by `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Record> {
        self.data.get(key)
    }

    /// A mutable reference to the record keyed by `key`, if any.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Record> {
        self.data.get_mut(key)
    }

    /// Store `value` under `key`, returning `value` (≈ Perl `set`).
    pub fn set(&mut self, key: &str, value: Record) -> Record {
        self.data.insert(key.to_string(), value.clone());
        value
    }

    /// Remove the record keyed by `key` (a no-op if absent).
    pub fn delete(&mut self, key: &str) {
        self.data.remove(key);
    }

    /// Every session id currently held (≈ `session_ids`).
    #[must_use]
    pub fn session_ids(&self) -> Vec<String> {
        self.data.keys().cloned().collect()
    }

    /// Read-modify-write the record keyed by `key`.
    ///
    /// The callback is the critical section: it runs with the record held
    /// exclusively and its mutation is written back.  A missing key is not
    /// created (Perl's callback receives `undef` and declines).  Returns the
    /// updated record, or `None` when there was none.
    pub fn update<F>(&mut self, key: &str, f: F) -> Option<Record>
    where
        F: FnOnce(&mut Record),
    {
        let rec = self.data.get_mut(key)?;
        f(rec);
        Some(rec.clone())
    }
}
