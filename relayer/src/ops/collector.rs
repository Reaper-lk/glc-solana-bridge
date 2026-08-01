//! Gathering a health report from live state (Phase 7h).
//!
//! The [`ReportSource`] the HTTP endpoint calls on every scrape. Everything
//! it reads is point-in-time: there is no cached snapshot, so a scrape can
//! never report a state the bridge has already left.
//!
//! # Reading fails soft, reporting fails loud
//!
//! A quantity that cannot be read this cycle is **omitted**, never defaulted
//! to zero. A vault balance of "0 because the node is down" and a vault
//! balance of "0 because it is empty" mean opposite things, and a monitor
//! that cannot tell them apart is worse than one that says nothing.
//!
//! The one exception is the report as a whole: if nothing at all could be
//! measured, `/health` returns 503 rather than a cheerful empty OK.

use std::sync::Arc;

use solana_sdk::pubkey::Pubkey;

use crate::glc::db::Db;
use crate::ops::health::{build_report, HealthReport, IndexerSummary, ReportSource};
use crate::ops::indexer_status::IndexerStatus;
use crate::ops::solvency::snapshot_from_db;
use crate::solana::epoch::EpochObservation;
use crate::solana::rpc::SolanaRpc;
use crate::withdrawal::executor::PayoutRpc;

/// SPL Mint layout: `supply` is a u64 at offset 36 (mint_authority COption
/// 36 bytes, then supply). Decoded by hand for the same reason every other
/// account here is — this workspace does not depend on anchor-lang or the
/// SPL program crates for decoding (owner decision R1).
const MINT_SUPPLY_OFFSET: usize = 36;

pub struct OpsCollector<R: SolanaRpc, P: PayoutRpc> {
    db_path: std::path::PathBuf,
    solana: R,
    goldcoin: P,
    wrapped_mint: Pubkey,
    vault_address: String,
    vault_min_confirmations: i64,
    epoch: Arc<EpochObservation>,
    /// Shared with the indexer loop. `None` for a deployment that reports on
    /// a database it does not itself index — the invariant is then omitted
    /// rather than guessed, since claiming an indexer is healthy when this
    /// process cannot see one would be worse than saying nothing.
    indexer: Option<Arc<IndexerStatus>>,
}

impl<R: SolanaRpc, P: PayoutRpc> OpsCollector<R, P> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db_path: std::path::PathBuf,
        solana: R,
        goldcoin: P,
        wrapped_mint: Pubkey,
        vault_address: String,
        vault_min_confirmations: i64,
        epoch: Arc<EpochObservation>,
    ) -> Self {
        OpsCollector {
            db_path,
            solana,
            goldcoin,
            wrapped_mint,
            vault_address,
            vault_min_confirmations,
            epoch,
            indexer: None,
        }
    }

    /// Attaches the indexer's shared status (Phase 7i), so `/health` reports
    /// a halted indexer instead of 200.
    pub fn with_indexer_status(mut self, status: Arc<IndexerStatus>) -> Self {
        self.indexer = Some(status);
        self
    }

    /// Wrapped supply from the SPL mint account, or `None` if unreadable.
    async fn wrapped_supply(&self) -> Option<u64> {
        let account = self.solana.get_account(&self.wrapped_mint).await.ok()??;
        let bytes = account
            .data
            .get(MINT_SUPPLY_OFFSET..MINT_SUPPLY_OFFSET + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// The vault's confirmed balance, or `None` if the node is unreachable.
    async fn vault_balance(&self) -> Option<u64> {
        let utxos = self
            .goldcoin
            .list_unspent(
                self.vault_min_confirmations,
                std::slice::from_ref(&self.vault_address),
            )
            .await
            .ok()?;
        Some(utxos.iter().map(|u| u.amount_atomic).sum())
    }

    async fn collect(&self) -> HealthReport {
        let Ok(db) = Db::open(&self.db_path) else {
            // No database, nothing measurable. An empty report is 503,
            // which is the correct answer.
            tracing::error!("ops collector could not open the database");
            return HealthReport::default();
        };

        let wrapped = self.wrapped_supply().await;
        let vault = self.vault_balance().await;

        let Ok(snapshot) = snapshot_from_db(&db, wrapped.unwrap_or(0), vault) else {
            tracing::error!("ops collector could not read solvency inputs");
            return HealthReport::default();
        };

        let halted_deposits = db
            .deposit_counts_by_state()
            .unwrap_or_default()
            .iter()
            .find(|(s, _)| s == "IntegrityHalted")
            .map(|(_, n)| *n)
            .unwrap_or(0);
        let withdrawal_counts = db.withdrawal_counts_by_state().unwrap_or_default();
        let halted_withdrawals = withdrawal_counts
            .iter()
            .find(|(s, _)| s == "IntegrityHalted")
            .map(|(_, n)| *n)
            .unwrap_or(0);

        let (utxo_count, utxo_value) = db.vault_utxo_stats().unwrap_or((0, 0));
        let mut extra: Vec<(String, f64, &'static str)> = vec![
            (
                "glc_vault_utxo_count".into(),
                utxo_count as f64,
                "Available vault UTXOs — a fragmentation signal",
            ),
            (
                "glc_vault_utxo_value_atomic".into(),
                utxo_value as f64,
                "Total value of available vault UTXOs, atomic units",
            ),
            (
                "glc_wrapped_supply_readable".into(),
                if wrapped.is_some() { 1.0 } else { 0.0 },
                "1 when the SPL mint supply could be read this scrape",
            ),
            (
                "glc_vault_balance_readable".into(),
                if vault.is_some() { 1.0 } else { 0.0 },
                "1 when the vault balance could be read this scrape",
            ),
        ];
        let _ = &mut extra;

        let borrowed: Vec<(&str, f64, &'static str)> =
            extra.iter().map(|(n, v, h)| (n.as_str(), *v, *h)).collect();

        let mut report = build_report(
            &snapshot,
            halted_deposits,
            halted_withdrawals,
            self.epoch.is_fresh_at(now_unix()),
            self.indexer.as_ref().map(|i| IndexerSummary {
                halted: i.is_halted(),
                halted_depth: i.halted_depth(),
                seconds_since_tick: i.seconds_since_tick(now_unix()),
                deepest_reorg: i.deepest_reorg(),
                max_reorg_depth: i.max_reorg_depth(),
            }),
            &borrowed,
        );

        // Per-state counts, appended to the rendered text so the pure
        // `build_report` stays free of database shapes.
        let mut states = String::new();
        states.push_str(
            "# HELP glc_deposits_by_state Deposits in each lifecycle state\n\
             # TYPE glc_deposits_by_state gauge\n",
        );
        for (state, n) in db.deposit_counts_by_state().unwrap_or_default() {
            states.push_str(&format!("glc_deposits_by_state{{state=\"{state}\"}} {n}\n"));
        }
        states.push_str(
            "# HELP glc_withdrawals_by_state Withdrawals in each lifecycle state\n\
             # TYPE glc_withdrawals_by_state gauge\n",
        );
        for (state, n) in withdrawal_counts {
            states.push_str(&format!(
                "glc_withdrawals_by_state{{state=\"{state}\"}} {n}\n"
            ));
        }
        report.metrics.push_str(&states);
        report
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl<R: SolanaRpc + Send + Sync + 'static, P: PayoutRpc + Send + Sync + 'static> ReportSource
    for OpsCollector<R, P>
{
    fn report(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthReport> + Send + '_>> {
        Box::pin(self.collect())
    }
}
