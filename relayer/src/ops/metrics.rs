//! A minimal metrics registry and Prometheus text encoder (Phase 7h).
//!
//! Hand-rolled rather than pulling a metrics crate, for the same reason the
//! Goldcoin RPC client is hand-rolled: the requirement is a few dozen gauges
//! and counters rendered as text, and this workspace's `deny.toml` is
//! already strained by the Solana stack. There is no dependency here at all.
//!
//! # Format
//!
//! Prometheus text exposition (owner decision H3): every operator toolchain
//! reads it, and it needs no schema negotiation. Each metric carries a
//! `# HELP` and `# TYPE` line, because a metric an operator cannot interpret
//! at 3am is not observability.
//!
//! # What is deliberately absent
//!
//! No histograms and no quantiles. They need either client-side bucketing
//! decisions this crate has no basis to make, or unbounded memory. Ages and
//! distributions are exposed as plain gauges (oldest, count per state) and
//! the operator's own scraper does the rest.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A metric's kind, as Prometheus understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonically increasing.
    Counter,
    /// Goes up and down.
    Gauge,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
        }
    }
}

/// One sample: a value plus its label set.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    /// Sorted so encoding is deterministic — a metrics endpoint that
    /// reorders between scrapes is needlessly hard to diff.
    labels: BTreeMap<String, String>,
    value: f64,
}

#[derive(Debug, Clone)]
struct Family {
    kind: Kind,
    help: String,
    samples: Vec<Sample>,
}

/// A registry built fresh for each scrape.
///
/// Deliberately not a long-lived global: every value here is derived from
/// the database or the chain at scrape time, so there is no state to keep
/// between scrapes and no risk of a stale gauge outliving what it described.
#[derive(Debug, Default)]
pub struct Registry {
    families: BTreeMap<String, Family>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Records a sample, creating the family if needed.
    pub fn record(
        &mut self,
        name: &str,
        kind: Kind,
        help: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) {
        let family = self
            .families
            .entry(name.to_string())
            .or_insert_with(|| Family {
                kind,
                help: help.to_string(),
                samples: Vec::new(),
            });
        family.samples.push(Sample {
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            value,
        });
    }

    /// Convenience for an unlabelled gauge.
    pub fn gauge(&mut self, name: &str, help: &str, value: f64) {
        self.record(name, Kind::Gauge, help, &[], value);
    }

    /// Convenience for an unlabelled counter.
    pub fn counter(&mut self, name: &str, help: &str, value: f64) {
        self.record(name, Kind::Counter, help, &[], value);
    }

    /// Renders the Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for (name, family) in &self.families {
            let _ = writeln!(out, "# HELP {name} {}", family.help);
            let _ = writeln!(out, "# TYPE {name} {}", family.kind.as_str());
            for s in &family.samples {
                if s.labels.is_empty() {
                    let _ = writeln!(out, "{name} {}", format_value(s.value));
                } else {
                    let labels: Vec<String> = s
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
                        .collect();
                    let _ = writeln!(
                        out,
                        "{name}{{{}}} {}",
                        labels.join(","),
                        format_value(s.value)
                    );
                }
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

/// Prometheus label values escape backslash, quote and newline. Nothing else.
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Renders a value the way Prometheus expects.
///
/// Only the non-finite cases need special handling. Rust's `f64` `Display`
/// never uses scientific notation and already omits the fractional part of
/// an integral value, so `21000000000.0` prints as `21000000000` — exactly
/// what an operator reading atomic-unit amounts needs.
///
/// An earlier version special-cased integers via `v as i64` on the theory
/// that `{}` would produce `2.1e10`. It does not, and the cast was worse
/// than useless: `as i64` **saturates**, so `1e20` rendered as
/// `9223372036854775807` — a plausible-looking wrong number in a metric an
/// operator would act on. Found by a surviving mutant, not by review.
fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_string()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf" } else { "-Inf" }.to_string()
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_help_and_type_before_samples() {
        // A metric an operator cannot interpret is not observability.
        let mut r = Registry::new();
        r.gauge(
            "glc_wrapped_supply",
            "Wrapped GLC supply in atomic units",
            42.0,
        );
        let out = r.encode();
        assert_eq!(
            out,
            "# HELP glc_wrapped_supply Wrapped GLC supply in atomic units\n\
             # TYPE glc_wrapped_supply gauge\n\
             glc_wrapped_supply 42\n"
        );
    }

    #[test]
    fn integral_values_render_without_a_decimal_point() {
        let mut r = Registry::new();
        r.gauge("v", "h", 21_000_000_000.0);
        assert!(r.encode().contains("v 21000000000\n"), "{}", r.encode());
    }

    #[test]
    fn values_beyond_i64_render_exactly_rather_than_saturating() {
        // The regression a surviving mutant exposed: an `as i64` cast
        // saturates, so this once rendered as 9223372036854775807 — a
        // plausible-looking wrong number in a metric an operator acts on.
        let mut r = Registry::new();
        r.gauge("huge", "h", 1e20);
        let out = r.encode();
        assert!(out.contains("huge 100000000000000000000\n"), "{out}");
        assert!(
            !out.contains("9223372036854775807"),
            "must not saturate at i64::MAX: {out}"
        );
    }

    #[test]
    fn fractional_values_keep_their_fraction() {
        let mut r = Registry::new();
        r.gauge("f", "h", 0.5);
        assert!(r.encode().contains("f 0.5\n"), "{}", r.encode());
    }

    #[test]
    fn labels_are_sorted_so_scrapes_are_diffable() {
        let mut r = Registry::new();
        r.record("m", Kind::Gauge, "h", &[("zeta", "1"), ("alpha", "2")], 1.0);
        assert!(
            r.encode().contains("m{alpha=\"2\",zeta=\"1\"} 1\n"),
            "{}",
            r.encode()
        );
    }

    #[test]
    fn families_are_sorted_so_scrapes_are_diffable() {
        let mut r = Registry::new();
        r.gauge("zzz", "h", 1.0);
        r.gauge("aaa", "h", 1.0);
        let out = r.encode();
        assert!(out.find("aaa").unwrap() < out.find("zzz").unwrap());
    }

    #[test]
    fn one_family_can_carry_many_labelled_samples() {
        let mut r = Registry::new();
        for (state, n) in [("Minted", 3.0), ("Confirming", 1.0)] {
            r.record(
                "glc_deposits",
                Kind::Gauge,
                "Deposits per state",
                &[("state", state)],
                n,
            );
        }
        let out = r.encode();
        assert_eq!(
            out.matches("# TYPE glc_deposits").count(),
            1,
            "one TYPE line"
        );
        assert!(out.contains("glc_deposits{state=\"Minted\"} 3\n"));
        assert!(out.contains("glc_deposits{state=\"Confirming\"} 1\n"));
    }

    #[test]
    fn label_values_are_escaped() {
        // A refusal reason ends up in a label; an unescaped quote would
        // produce output no scraper can parse.
        let mut r = Registry::new();
        r.record("m", Kind::Gauge, "h", &[("reason", "a\"b\\c\nd")], 1.0);
        assert!(
            r.encode().contains(r#"m{reason="a\"b\\c\nd"} 1"#),
            "{}",
            r.encode()
        );
    }

    #[test]
    fn non_finite_values_render_as_prometheus_expects() {
        let mut r = Registry::new();
        r.gauge("nan", "h", f64::NAN);
        r.gauge("pinf", "h", f64::INFINITY);
        r.gauge("ninf", "h", f64::NEG_INFINITY);
        let out = r.encode();
        assert!(out.contains("nan NaN\n"));
        assert!(out.contains("pinf +Inf\n"));
        assert!(out.contains("ninf -Inf\n"));
    }

    #[test]
    fn an_empty_registry_encodes_to_nothing() {
        assert!(Registry::new().is_empty());
        assert_eq!(Registry::new().encode(), "");
    }

    #[test]
    fn counters_and_gauges_are_typed_distinctly() {
        let mut r = Registry::new();
        r.counter("c", "h", 1.0);
        r.gauge("g", "h", 1.0);
        let out = r.encode();
        assert!(out.contains("# TYPE c counter\n"));
        assert!(out.contains("# TYPE g gauge\n"));
    }
}
