//! The operator-facing HTTP surface (Phase 7h, ADR-0014 §13).
//!
//! Two read-only endpoints:
//!
//! | path | purpose |
//! |---|---|
//! | `/health` | one line per invariant, and an HTTP status an uptime check can read |
//! | `/metrics` | Prometheus text exposition |
//!
//! # It exposes; it does not page
//!
//! No alerting integration lives here (owner decision H2). `/health`
//! returns **503** when any page-immediately invariant is breached, so an
//! operator's existing uptime monitoring raises the alarm using credentials
//! this process never sees.
//!
//! # Bind it privately
//!
//! There is no authentication, because adding one would mean this process
//! holding another secret. The endpoint reveals balances, supply, and
//! per-state counts — operational detail, not key material, but not public
//! either. Bind it to a private interface or a loopback address behind the
//! operator's own proxy. `main.rs` logs the bind address at startup so a
//! mistake here is visible in review.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::ops::metrics::Registry;
use crate::ops::solvency::SolvencySnapshot;

/// One thing an operator is expected to be paged about (ADR-0014 §13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invariant {
    pub name: &'static str,
    pub healthy: bool,
    pub detail: String,
}

/// Everything the endpoint reports, rebuilt on every scrape.
#[derive(Debug, Clone, Default)]
pub struct HealthReport {
    pub invariants: Vec<Invariant>,
    /// Rendered Prometheus text.
    pub metrics: String,
}

impl HealthReport {
    /// Whether every page-immediately invariant holds.
    ///
    /// An empty report is **not** healthy: it means the collector produced
    /// nothing, and a monitor that reports OK when it has measured nothing
    /// is worse than no monitor.
    pub fn healthy(&self) -> bool {
        !self.invariants.is_empty() && self.invariants.iter().all(|i| i.healthy)
    }

    pub fn status(&self) -> StatusCode {
        if self.healthy() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }

    /// The plain-text body of `/health`, one line per invariant.
    pub fn text(&self) -> String {
        if self.invariants.is_empty() {
            return "UNKNOWN no invariants were evaluated\n".to_string();
        }
        let mut out = String::new();
        for i in &self.invariants {
            out.push_str(if i.healthy { "OK   " } else { "BREACH " });
            out.push_str(i.name);
            if !i.detail.is_empty() {
                out.push_str(": ");
                out.push_str(&i.detail);
            }
            out.push('\n');
        }
        out
    }
}

/// Builds the invariant list and metric registry from a solvency snapshot
/// plus whatever else the caller has gathered.
///
/// Pure: takes measurements, returns a report. Everything that touches a
/// database or a chain happens in the caller, which is what makes the
/// reporting logic testable without either.
/// The indexer facts the report needs, flattened by the caller so
/// [`build_report`] stays free of shared state and remains a pure function
/// of its measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexerSummary {
    pub halted: bool,
    /// Meaningless unless `halted`.
    pub halted_depth: i64,
    pub seconds_since_tick: i64,
    /// ADR-0014 §13.1 item 5 — the deepest reorg rolled back so far, and the
    /// ceiling beyond which the indexer halts. Gauges, not an invariant: a
    /// deep-but-survivable reorg is a fact about the chain, not a fault in
    /// the bridge, and the threshold that should worry a given deployment is
    /// the operator's to set (owner decision H2).
    pub deepest_reorg: i64,
    pub max_reorg_depth: i64,
}

pub fn build_report(
    snapshot: &SolvencySnapshot,
    halted_deposits: u64,
    halted_withdrawals: u64,
    epoch_is_fresh: bool,
    indexer: Option<IndexerSummary>,
    extra: &[(&str, f64, &'static str)],
) -> HealthReport {
    let mut invariants = Vec::new();

    // §13.1 (1) — the master solvency invariant. Measured to hold with
    // exactly zero slack, so any breach is real.
    invariants.push(Invariant {
        name: "solvency",
        healthy: snapshot.invariant_holds(),
        detail: if snapshot.invariant_holds() {
            format!(
                "wrapped {} <= deposits-payouts {}",
                snapshot.wrapped_supply,
                snapshot.backing_bound()
            )
        } else {
            format!(
                "wrapped {} EXCEEDS deposits-payouts {} by {}",
                snapshot.wrapped_supply,
                snapshot.backing_bound(),
                snapshot.breach_atomic()
            )
        },
    });

    // §13.1 (2) — vault reconciliation. ADR-0013 D3's fee drift is EXPECTED
    // and is not a breach (ADR-0020); drift beyond the fees we know we paid
    // is a different matter and is what this alarms on.
    if let (Some(drift), Some(unexplained)) = (
        snapshot.fee_drift_atomic(),
        snapshot.unexplained_drift_atomic(),
    ) {
        invariants.push(Invariant {
            name: "vault_reconciliation",
            healthy: unexplained == 0,
            detail: if unexplained == 0 {
                format!(
                    "drift {drift} fully explained by {} in fees",
                    snapshot.vault_fees_paid
                )
            } else {
                format!(
                    "drift {drift} exceeds {} in known fees by {unexplained}",
                    snapshot.vault_fees_paid
                )
            },
        });
    }

    // §13.1 (3) — any integrity halt.
    let halted = halted_deposits + halted_withdrawals;
    invariants.push(Invariant {
        name: "no_integrity_halts",
        healthy: halted == 0,
        detail: format!("{halted_deposits} deposits, {halted_withdrawals} withdrawals halted"),
    });

    // §13.1 (4) — a validator whose epoch view has gone stale cannot be
    // trusted to agree with its peers about anything.
    invariants.push(Invariant {
        name: "validator_epoch_fresh",
        healthy: epoch_is_fresh,
        detail: if epoch_is_fresh {
            String::new()
        } else {
            "epoch observation is stale".to_string()
        },
    });

    // Phase 7i — a halted indexer stops crediting deposits and never
    // resolves on its own, yet the process stays alive for liveness probes.
    // Without this the bridge could stop observing Goldcoin entirely and
    // still report 200 (ops::indexer_status).
    if let Some(i) = indexer {
        invariants.push(Invariant {
            name: "indexer_not_halted",
            healthy: !i.halted,
            detail: if i.halted {
                format!(
                    "HALTED on a reorg deeper than max_reorg_depth (attempted {}); \
                     deposits are no longer being indexed and an operator must intervene",
                    i.halted_depth
                )
            } else {
                format!("last tick {}s ago", i.seconds_since_tick)
            },
        });
    }

    let mut r = Registry::new();
    if let Some(i) = indexer {
        r.gauge(
            "glc_indexer_halted",
            "1 when the Goldcoin indexer has halted on an over-deep reorg and requires an operator",
            u8::from(i.halted) as f64,
        );
        // A gauge, deliberately not an invariant: a quiet chain produces no
        // blocks and a brief node outage is retried, so this crate has no
        // basis for the threshold that separates slow from broken. The
        // operator's scraper decides (owner decision H2).
        r.gauge(
            "glc_indexer_seconds_since_tick",
            "Seconds since the Goldcoin indexer last completed a tick without halting",
            i.seconds_since_tick as f64,
        );
        // §13.1 (5): the early warning. The halt above is the failure; this
        // is what lets an operator see it coming.
        r.gauge(
            "glc_reorg_deepest_observed",
            "Deepest Goldcoin reorg this process has rolled back, in blocks",
            i.deepest_reorg as f64,
        );
        r.gauge(
            "glc_reorg_max_depth_configured",
            "Configured max_reorg_depth; beyond this the indexer halts",
            i.max_reorg_depth as f64,
        );
    }
    r.gauge(
        "glc_wrapped_supply_atomic",
        "Wrapped GLC supply reported by the SPL mint, atomic units",
        snapshot.wrapped_supply as f64,
    );
    r.gauge(
        "glc_confirmed_deposits_atomic",
        "Total value of deposits observed minted, atomic units",
        snapshot.confirmed_deposits as f64,
    );
    r.gauge(
        "glc_completed_payouts_atomic",
        "Total paid out to users across completed payouts, atomic units",
        snapshot.completed_payouts as f64,
    );
    r.gauge(
        "glc_backing_bound_atomic",
        "Upper bound on wrapped supply: confirmed deposits minus completed payouts",
        snapshot.backing_bound() as f64,
    );
    r.gauge(
        "glc_solvency_breach_atomic",
        "Wrapped supply in excess of the backing bound. MUST be zero",
        snapshot.breach_atomic() as f64,
    );
    r.gauge(
        "glc_vault_fees_paid_atomic",
        "Cumulative Goldcoin fees absorbed by the vault (ADR-0013 D3). Grows with payout count; \
         replenished from an external reserve, NOT a solvency breach",
        snapshot.vault_fees_paid as f64,
    );
    if let Some(bal) = snapshot.vault_balance {
        r.gauge(
            "glc_vault_balance_atomic",
            "Confirmed on-chain vault balance, atomic units",
            bal as f64,
        );
    }
    if let Some(drift) = snapshot.fee_drift_atomic() {
        r.gauge(
            "glc_vault_fee_drift_atomic",
            "Vault balance shortfall against the backing bound. Expected to track \
             glc_vault_fees_paid_atomic",
            drift as f64,
        );
    }
    if let Some(u) = snapshot.unexplained_drift_atomic() {
        r.gauge(
            "glc_vault_unexplained_drift_atomic",
            "Vault shortfall NOT explained by fees this relayer recorded. MUST be zero",
            u as f64,
        );
    }
    r.gauge(
        "glc_integrity_halted_deposits",
        "Deposits in the terminal IntegrityHalted state",
        halted_deposits as f64,
    );
    r.gauge(
        "glc_integrity_halted_withdrawals",
        "Withdrawals in the terminal IntegrityHalted state",
        halted_withdrawals as f64,
    );
    r.gauge(
        "glc_validator_epoch_fresh",
        "1 when this relayer's validator-epoch observation is current, 0 when stale",
        if epoch_is_fresh { 1.0 } else { 0.0 },
    );
    for (name, value, help) in extra {
        r.gauge(name, help, *value);
    }
    r.gauge(
        "glc_health",
        "1 when every page-immediately invariant holds, 0 otherwise",
        if invariants.iter().all(|i| i.healthy) {
            1.0
        } else {
            0.0
        },
    );

    HealthReport {
        invariants,
        metrics: r.encode(),
    }
}

/// Produces a fresh report. Called once per request, so a scrape always
/// reflects the state at scrape time rather than a cached snapshot.
pub trait ReportSource: Send + Sync + 'static {
    fn report(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthReport> + Send + '_>>;
}

async fn handle<S: ReportSource>(
    req: Request<hyper::body::Incoming>,
    source: Arc<S>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, content_type, body) = match req.uri().path() {
        "/health" => {
            let report = source.report().await;
            (report.status(), "text/plain; charset=utf-8", report.text())
        }
        "/metrics" => {
            let report = source.report().await;
            // Always 200: a scrape failing because the bridge is unhealthy
            // would lose the very metrics an operator needs to diagnose it.
            (
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                report.metrics,
            )
        }
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", content_type)
        // Nothing here is ever worth caching: every value is a point-in-time
        // reading.
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("well-formed response"))
}

/// Serves `/health` and `/metrics` until shutdown.
pub async fn serve<S: ReportSource>(
    addr: SocketAddr,
    source: Arc<S>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "health and metrics endpoint listening (bind this privately)");
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("health endpoint: shutdown signal received, exiting");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        // A failed accept must never take the endpoint down:
                        // losing observability during an incident is exactly
                        // when it is least affordable.
                        tracing::warn!(error = %e, "health endpoint: accept failed");
                        continue;
                    }
                };
                let source = Arc::clone(&source);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| handle(req, Arc::clone(&source)));
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!(%peer, error = %e, "health connection ended");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(
        supply: u64,
        deposits: u64,
        payouts: u64,
        fees: u64,
        vault: Option<u64>,
    ) -> SolvencySnapshot {
        SolvencySnapshot {
            wrapped_supply: supply,
            confirmed_deposits: deposits,
            completed_payouts: payouts,
            vault_fees_paid: fees,
            vault_balance: vault,
        }
    }

    /// The measured normal shape, in ATOMIC units: bound met exactly, vault
    /// short by exactly the fees paid. Numbers taken from the regtest run
    /// that motivated ADR-0020 (210 GLC supply, 904 atomic units of fees).
    const SUPPLY: u64 = 21_000_000_000;
    const DEPOSITS: u64 = 25_000_000_000;
    const PAYOUTS: u64 = 4_000_000_000;
    const FEES: u64 = 904;

    fn healthy_snapshot() -> SolvencySnapshot {
        snap(SUPPLY, DEPOSITS, PAYOUTS, FEES, Some(SUPPLY - FEES))
    }

    #[test]
    fn the_normal_measured_state_is_reported_healthy() {
        // Fee drift is present and must NOT make the endpoint unhealthy —
        // otherwise the alarm is red from the first payout and useless.
        let r = build_report(&healthy_snapshot(), 0, 0, true, None, &[]);
        assert!(r.healthy(), "{}", r.text());
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.text().contains("OK   solvency"));
        assert!(r.text().contains("fully explained by 904 in fees"));
    }

    #[test]
    fn a_halted_indexer_is_unhealthy_even_when_everything_else_holds() {
        // The gap this closes: before Phase 7i the bridge could stop
        // observing Goldcoin entirely and still report 200, because the
        // halt lived in the indexer task's own memory and the process stays
        // alive for liveness probes.
        let r = build_report(
            &healthy_snapshot(),
            0,
            0,
            true,
            Some(IndexerSummary {
                halted: true,
                halted_depth: 120,
                seconds_since_tick: 5,
                deepest_reorg: 0,
                max_reorg_depth: 0,
            }),
            &[],
        );
        assert!(!r.healthy(), "a halted indexer must fail the health check");
        let halt = r
            .invariants
            .iter()
            .find(|i| i.name == "indexer_not_halted")
            .expect("the invariant is present");
        assert!(!halt.healthy);
        assert!(halt.detail.contains("120"), "{}", halt.detail);
        assert!(
            r.metrics.contains("glc_indexer_halted 1\n"),
            "{}",
            r.metrics
        );
    }

    #[test]
    fn a_working_indexer_is_healthy_and_reports_its_freshness() {
        let r = build_report(
            &healthy_snapshot(),
            0,
            0,
            true,
            Some(IndexerSummary {
                halted: false,
                halted_depth: 0,
                seconds_since_tick: 42,
                deepest_reorg: 0,
                max_reorg_depth: 0,
            }),
            &[],
        );
        assert!(r.healthy());
        assert!(
            r.metrics.contains("glc_indexer_halted 0\n"),
            "{}",
            r.metrics
        );
        assert!(
            r.metrics.contains("glc_indexer_seconds_since_tick 42\n"),
            "{}",
            r.metrics
        );
    }

    #[test]
    fn staleness_alone_is_a_gauge_and_never_an_alarm() {
        // A quiet chain produces no blocks and a brief node outage is
        // retried. This crate has no basis for the threshold that separates
        // slow from broken, so it exposes the number and pages on nothing
        // (owner decision H2).
        let r = build_report(
            &healthy_snapshot(),
            0,
            0,
            true,
            Some(IndexerSummary {
                halted: false,
                halted_depth: 0,
                seconds_since_tick: 86_400,
                deepest_reorg: 0,
                max_reorg_depth: 0,
            }),
            &[],
        );
        assert!(
            r.healthy(),
            "one day of silence is not, by itself, a breach"
        );
        assert!(r.metrics.contains("glc_indexer_seconds_since_tick 86400\n"));
    }

    #[test]
    fn reorg_depth_is_exposed_as_an_early_warning_and_never_as_a_breach() {
        // ADR-0014 §13.1 (5). A deep-but-survivable reorg is a fact about
        // the chain, not a fault in the bridge: the operator's scraper picks
        // the threshold that should worry their deployment (owner decision
        // H2). The halt is the failure; this is what lets them see it
        // coming.
        let r = build_report(
            &healthy_snapshot(),
            0,
            0,
            true,
            Some(IndexerSummary {
                halted: false,
                halted_depth: 0,
                seconds_since_tick: 5,
                deepest_reorg: 48,
                max_reorg_depth: 50,
            }),
            &[],
        );
        assert!(
            r.healthy(),
            "a reorg at 48 of 50 is alarming but is not a bridge fault"
        );
        assert!(
            r.metrics.contains("glc_reorg_deepest_observed 48\n"),
            "{}",
            r.metrics
        );
        assert!(
            r.metrics.contains("glc_reorg_max_depth_configured 50\n"),
            "the ceiling must be exposed too, or 48 cannot be read as a ratio: {}",
            r.metrics
        );
    }

    #[test]
    fn a_report_without_an_indexer_omits_the_invariant_rather_than_assuming_health() {
        // Claiming an indexer is healthy when this process cannot see one
        // would be worse than saying nothing about it.
        let r = build_report(&healthy_snapshot(), 0, 0, true, None, &[]);
        assert!(!r.invariants.iter().any(|i| i.name == "indexer_not_halted"));
        assert!(!r.metrics.contains("glc_indexer_halted"));
    }

    #[test]
    fn a_solvency_breach_is_reported_and_returns_503() {
        let r = build_report(
            &snap(SUPPLY + 90, DEPOSITS, PAYOUTS, 0, Some(SUPPLY)),
            0,
            0,
            true,
            None,
            &[],
        );
        assert!(!r.healthy());
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(r.text().contains("BREACH solvency"), "{}", r.text());
        assert!(r.metrics.contains("glc_solvency_breach_atomic 90"));
    }

    #[test]
    fn drift_beyond_known_fees_breaches_reconciliation_but_not_solvency() {
        // Value left the vault that no payout of ours accounts for. That is
        // a different alarm from insolvency and must not be conflated.
        let r = build_report(
            &snap(SUPPLY, DEPOSITS, PAYOUTS, FEES, Some(SUPPLY - 50_000)),
            0,
            0,
            true,
            None,
            &[],
        );
        assert!(!r.healthy());
        assert!(r.text().contains("OK   solvency"), "{}", r.text());
        assert!(
            r.text().contains("BREACH vault_reconciliation"),
            "{}",
            r.text()
        );
    }

    #[test]
    fn an_integrity_halt_is_a_page() {
        let r = build_report(&healthy_snapshot(), 1, 0, true, None, &[]);
        assert!(!r.healthy());
        assert!(
            r.text().contains("BREACH no_integrity_halts"),
            "{}",
            r.text()
        );
        assert!(r.metrics.contains("glc_integrity_halted_deposits 1"));
    }

    #[test]
    fn a_stale_epoch_is_a_page() {
        let r = build_report(&healthy_snapshot(), 0, 0, false, None, &[]);
        assert!(!r.healthy());
        assert!(r.text().contains("BREACH validator_epoch_fresh"));
        assert!(r.metrics.contains("glc_validator_epoch_fresh 0"));
    }

    #[test]
    fn an_empty_report_is_never_healthy() {
        // A monitor that says OK when it has measured nothing is worse than
        // no monitor.
        let empty = HealthReport::default();
        assert!(!empty.healthy());
        assert_eq!(empty.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(empty.text().contains("UNKNOWN"));
    }

    #[test]
    fn an_unreadable_vault_omits_reconciliation_rather_than_guessing() {
        let r = build_report(
            &snap(SUPPLY, DEPOSITS, PAYOUTS, FEES, None),
            0,
            0,
            true,
            None,
            &[],
        );
        assert!(
            !r.text().contains("vault_reconciliation"),
            "an absent reading must not be reported as a passing check: {}",
            r.text()
        );
        assert!(!r.metrics.contains("glc_vault_balance_atomic"));
        assert!(r.healthy(), "and it must not fail the endpoint either");
    }

    #[test]
    fn the_fee_drift_is_always_exported_even_when_healthy() {
        // The whole point of ADR-0020: visible, bounded, auditable.
        let r = build_report(&healthy_snapshot(), 0, 0, true, None, &[]);
        assert!(r.metrics.contains("glc_vault_fees_paid_atomic 904"));
        assert!(r.metrics.contains("glc_vault_fee_drift_atomic 904"));
        assert!(r.metrics.contains("glc_vault_unexplained_drift_atomic 0"));
    }

    #[test]
    fn the_health_gauge_tracks_the_endpoint_status() {
        assert!(build_report(&healthy_snapshot(), 0, 0, true, None, &[])
            .metrics
            .contains("glc_health 1"));
        assert!(build_report(&healthy_snapshot(), 1, 0, true, None, &[])
            .metrics
            .contains("glc_health 0"));
    }

    #[test]
    fn extra_gauges_are_passed_through() {
        let r = build_report(
            &healthy_snapshot(),
            0,
            0,
            true,
            None,
            &[("glc_custom", 7.0, "help")],
        );
        assert!(r.metrics.contains("glc_custom 7"));
        assert!(r.metrics.contains("# HELP glc_custom help"));
    }

    #[test]
    fn every_exported_metric_carries_help_and_type() {
        let r = build_report(&healthy_snapshot(), 0, 0, true, None, &[]);
        let names: Vec<&str> = r
            .metrics
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split(['{', ' ']).next().unwrap())
            .collect();
        assert!(!names.is_empty());
        for n in names {
            assert!(
                r.metrics.contains(&format!("# HELP {n} ")),
                "{n} has no HELP line"
            );
            assert!(
                r.metrics.contains(&format!("# TYPE {n} ")),
                "{n} has no TYPE line"
            );
        }
    }
}
