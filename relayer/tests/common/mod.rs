//! Shared test support.
//!
//! Currently one thing: capturing `tracing` events so a test can assert that
//! an audit record was actually emitted (ADR-0014 §13.3). It lives here
//! rather than being copied into each suite because the suites that need it
//! are the ones that already own heavyweight fixtures, and a third copy of a
//! subscriber is a third thing to keep in step.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::subscriber::with_default;

#[derive(Debug, Clone, Default)]
pub struct Captured {
    pub fields: Vec<(String, String)>,
    pub level: String,
}

impl Captured {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct Collector {
    events: Arc<Mutex<Vec<Captured>>>,
}

struct FieldVisitor(Vec<(String, String)>);

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl tracing::Subscriber for Collector {
    fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _s: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _s: &tracing::span::Id, _v: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _s: &tracing::span::Id, _f: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut v = FieldVisitor(Vec::new());
        event.record(&mut v);
        self.events.lock().unwrap().push(Captured {
            fields: v.0,
            level: event.metadata().level().to_string(),
        });
    }
    fn enter(&self, _s: &tracing::span::Id) {}
    fn exit(&self, _s: &tracing::span::Id) {}
}

/// Runs `f` and returns its output plus every `signature_granted` event it
/// emitted.
pub fn capture_grants<T>(f: impl FnOnce() -> T) -> (T, Vec<Captured>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let out = with_default(
        Collector {
            events: Arc::clone(&events),
        },
        f,
    );
    let grants = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.get("event") == Some(glc_relayer::p2p::audit_log::EVENT))
        .cloned()
        .collect();
    (out, grants)
}

/// Same, for an async body.
pub async fn capture_grants_async<T, F: std::future::Future<Output = T>>(
    f: F,
) -> (T, Vec<Captured>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Collector {
        events: Arc::clone(&events),
    });
    let out = f.await;
    drop(_guard);
    let grants = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.get("event") == Some(glc_relayer::p2p::audit_log::EVENT))
        .cloned()
        .collect();
    (out, grants)
}
