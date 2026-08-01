//! The health and metrics endpoint, end to end over real HTTP (Phase 7h).
//!
//! Drives a real `hyper` server on a real socket. The reporting logic is
//! unit-tested in `ops::health`; what these add is that the HTTP surface
//! actually behaves — status codes, content types, and the 503 an operator's
//! uptime check reads.

use std::sync::Arc;

use glc_relayer::ops::health::{build_report, serve, HealthReport, ReportSource};
use glc_relayer::ops::solvency::SolvencySnapshot;

const SUPPLY: u64 = 21_000_000_000;
const DEPOSITS: u64 = 25_000_000_000;
const PAYOUTS: u64 = 4_000_000_000;
const FEES: u64 = 904;

struct Fixed(HealthReport);

impl ReportSource for Fixed {
    fn report(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthReport> + Send + '_>> {
        let r = self.0.clone();
        Box::pin(async move { r })
    }
}

fn snapshot(vault: Option<u64>) -> SolvencySnapshot {
    SolvencySnapshot {
        wrapped_supply: SUPPLY,
        confirmed_deposits: DEPOSITS,
        completed_payouts: PAYOUTS,
        vault_fees_paid: FEES,
        vault_balance: vault,
    }
}

/// Serves `report` on an ephemeral port and returns its address plus a
/// shutdown handle.
async fn spawn(report: HealthReport) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // `serve` binds it itself; this just reserves a free port
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(serve(addr, Arc::new(Fixed(report)), rx));
    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    (format!("http://{addr}"), tx)
}

async fn get(url: &str) -> (u16, String, String) {
    let resp = reqwest::get(url).await.expect("request");
    let status = resp.status().as_u16();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, ctype, resp.text().await.unwrap())
}

#[tokio::test]
async fn a_healthy_bridge_serves_200_on_health() {
    let report = build_report(&snapshot(Some(SUPPLY - FEES)), 0, 0, true, &[]);
    let (base, _tx) = spawn(report).await;
    let (status, ctype, body) = get(&format!("{base}/health")).await;
    assert_eq!(status, 200);
    assert!(ctype.starts_with("text/plain"));
    assert!(body.contains("OK   solvency"), "{body}");
}

#[tokio::test]
async fn a_breached_invariant_serves_503_so_uptime_checks_alarm() {
    // The whole alerting story: the relayer pages nobody, it just fails an
    // HTTP check the operator is already watching.
    let mut bad = snapshot(Some(SUPPLY));
    bad.wrapped_supply = SUPPLY + 1;
    let (base, _tx) = spawn(build_report(&bad, 0, 0, true, &[])).await;
    let (status, _, body) = get(&format!("{base}/health")).await;
    assert_eq!(status, 503);
    assert!(body.contains("BREACH solvency"), "{body}");
}

#[tokio::test]
async fn metrics_serve_200_even_when_the_bridge_is_unhealthy() {
    // A scrape that fails because the bridge is broken would lose exactly
    // the data needed to diagnose it.
    let (base, _tx) = spawn(build_report(
        &snapshot(Some(SUPPLY - FEES)),
        5,
        2,
        false,
        &[],
    ))
    .await;
    let (status, ctype, body) = get(&format!("{base}/metrics")).await;
    assert_eq!(status, 200, "metrics must stay scrapable when unhealthy");
    assert!(ctype.contains("version=0.0.4"), "{ctype}");
    assert!(body.contains("glc_integrity_halted_deposits 5"), "{body}");
    assert!(body.contains("glc_health 0"), "{body}");
}

#[tokio::test]
async fn the_fee_drift_is_exported_on_a_healthy_bridge() {
    // ADR-0020: visible, bounded, auditable — not hidden because it is
    // "normal".
    let (base, _tx) = spawn(build_report(
        &snapshot(Some(SUPPLY - FEES)),
        0,
        0,
        true,
        &[],
    ))
    .await;
    let (status, _, body) = get(&format!("{base}/metrics")).await;
    assert_eq!(status, 200);
    assert!(body.contains("glc_vault_fees_paid_atomic 904"), "{body}");
    assert!(body.contains("glc_vault_fee_drift_atomic 904"), "{body}");
    assert!(
        body.contains("glc_vault_unexplained_drift_atomic 0"),
        "{body}"
    );
}

#[tokio::test]
async fn an_unknown_path_is_404() {
    let (base, _tx) = spawn(build_report(
        &snapshot(Some(SUPPLY - FEES)),
        0,
        0,
        true,
        &[],
    ))
    .await;
    assert_eq!(get(&format!("{base}/../etc/passwd")).await.0, 404);
    assert_eq!(get(&format!("{base}/")).await.0, 404);
}

#[tokio::test]
async fn nothing_is_cacheable() {
    // Every value is a point-in-time reading; a cached one is a lie.
    let (base, _tx) = spawn(build_report(
        &snapshot(Some(SUPPLY - FEES)),
        0,
        0,
        true,
        &[],
    ))
    .await;
    let resp = reqwest::get(format!("{base}/metrics")).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn an_empty_report_serves_503_rather_than_a_cheerful_ok() {
    // The collector could measure nothing. Reporting OK would be worse than
    // reporting nothing at all.
    let (base, _tx) = spawn(HealthReport::default()).await;
    let (status, _, body) = get(&format!("{base}/health")).await;
    assert_eq!(status, 503);
    assert!(body.contains("UNKNOWN"), "{body}");
}

#[tokio::test]
async fn the_endpoint_survives_many_sequential_scrapes() {
    // Prometheus scrapes forever; a connection leak would surface here.
    let (base, _tx) = spawn(build_report(
        &snapshot(Some(SUPPLY - FEES)),
        0,
        0,
        true,
        &[],
    ))
    .await;
    for i in 0..25 {
        assert_eq!(get(&format!("{base}/metrics")).await.0, 200, "scrape {i}");
    }
}
