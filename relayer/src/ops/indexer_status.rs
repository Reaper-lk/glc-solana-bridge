//! Whether the Goldcoin indexer is still working (Phase 7i).
//!
//! # Why this exists
//!
//! Verifying the deep-reorg runbook found that a **halted indexer was
//! invisible**. On a reorg deeper than `max_reorg_depth` the indexer stops
//! writing and refuses to progress until an operator intervenes (ADR-0011,
//! a deliberate security property — it never guesses a fork point). But:
//!
//! - the halt lived in process-local memory, reachable only by the indexer
//!   task itself;
//! - `/health` kept reporting 200, because none of its four invariants
//!   covers indexing;
//! - the process deliberately stays alive so orchestration liveness probes
//!   keep passing.
//!
//! So a bridge that had stopped observing Goldcoin entirely looked healthy
//! from every angle an operator monitors. The only evidence was one
//! `tracing::error!` line, once, possibly hours earlier.
//!
//! That is not a safety failure — a halted indexer mints nothing, so it
//! fails closed — but deposits silently stop being credited, and the
//! runbook's *detection* step had no honest answer beyond "grep the logs".
//! A runbook step that cannot be performed is what this whole phase exists
//! to eliminate.
//!
//! # What is and is not an invariant
//!
//! The **halt** is an invariant: it is unambiguous, requires an operator,
//! and never resolves on its own.
//!
//! Time since the last successful tick is exposed as a **gauge only**. A
//! quiet chain produces no blocks, and a node being briefly unreachable is
//! retried — neither is a fault, and this crate has no basis for choosing
//! the threshold that separates "slow" from "broken". The operator's own
//! scraper decides (owner decision H2: expose, never page).

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Shared between the indexer loop and the ops collector, the same way
/// [`crate::solana::epoch::EpochObservation`] is shared between the epoch
/// refresher and everything that reads the epoch.
#[derive(Debug)]
pub struct IndexerStatus {
    halted: AtomicBool,
    /// The depth that triggered the halt, for the report. Meaningless while
    /// `halted` is false.
    halted_depth: AtomicI64,
    /// Unix seconds of the last tick that completed **without** halting.
    last_tick_unix: AtomicI64,
    /// The deepest reorg this process has rolled back (ADR-0014 §13.1 item
    /// 5). Exposed so an operator sees a chain trending toward
    /// `max_reorg_depth` **before** the indexer halts on it — the halt is
    /// the failure, not the warning.
    deepest_reorg: AtomicI64,
    /// The configured ceiling, so the gauge can be read as a ratio without
    /// the scraper having to know the deployment's configuration.
    max_reorg_depth: AtomicI64,
}

impl IndexerStatus {
    /// Starts un-halted, with the first tick not yet recorded.
    ///
    /// `started_at` seeds `last_tick_unix` so the "seconds since a tick"
    /// gauge measures from process start rather than from the epoch, which
    /// would read as decades of silence on the first scrape.
    pub fn new(started_at: i64) -> Self {
        IndexerStatus {
            halted: AtomicBool::new(false),
            halted_depth: AtomicI64::new(0),
            last_tick_unix: AtomicI64::new(started_at),
            deepest_reorg: AtomicI64::new(0),
            max_reorg_depth: AtomicI64::new(0),
        }
    }

    /// Records the configured ceiling once at startup.
    pub fn set_max_reorg_depth(&self, depth: i64) {
        self.max_reorg_depth.store(depth, Ordering::SeqCst);
    }

    /// Records a rolled-back reorg. Keeps the **deepest** seen, not the
    /// most recent: a single 40-block reorg an hour ago is what an operator
    /// needs to know about, and a later 1-block reorg must not erase it.
    pub fn record_reorg(&self, depth: i64) {
        self.deepest_reorg.fetch_max(depth, Ordering::SeqCst);
    }

    pub fn deepest_reorg(&self) -> i64 {
        self.deepest_reorg.load(Ordering::SeqCst)
    }

    pub fn max_reorg_depth(&self) -> i64 {
        self.max_reorg_depth.load(Ordering::SeqCst)
    }

    /// Records a tick that did real work (or found nothing to do).
    pub fn record_tick(&self, at_unix: i64) {
        self.last_tick_unix.store(at_unix, Ordering::SeqCst);
    }

    /// Records the halt. Deliberately one-way: the indexer itself never
    /// clears it, because clearing it means an operator has widened
    /// `max_reorg_depth` and restarted the process.
    pub fn record_halt(&self, attempted_depth: i64) {
        // Depth first, then the flag that vouches for it, so a concurrent
        // reader can never see `halted` with a stale depth beside it — the
        // same ordering discipline `EpochObservation::record` uses.
        self.halted_depth.store(attempted_depth, Ordering::SeqCst);
        self.halted.store(true, Ordering::SeqCst);
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    pub fn halted_depth(&self) -> i64 {
        self.halted_depth.load(Ordering::SeqCst)
    }

    pub fn last_tick_unix(&self) -> i64 {
        self.last_tick_unix.load(Ordering::SeqCst)
    }

    /// Seconds since the last non-halting tick, floored at zero.
    ///
    /// Clamped because a clock that steps backwards must not report negative
    /// staleness, which would read as "very recent" to a threshold check.
    pub fn seconds_since_tick(&self, now_unix: i64) -> i64 {
        now_unix.saturating_sub(self.last_tick_unix()).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deepest_reorg_is_kept_not_the_most_recent() {
        // A 40-block reorg an hour ago is the fact an operator needs; a
        // later 1-block reorg must not erase it.
        let s = IndexerStatus::new(1_000);
        assert_eq!(s.deepest_reorg(), 0);
        s.record_reorg(40);
        s.record_reorg(1);
        assert_eq!(s.deepest_reorg(), 40);
        s.record_reorg(41);
        assert_eq!(s.deepest_reorg(), 41);
    }

    #[test]
    fn the_configured_ceiling_is_reported_alongside_it() {
        // Without it a scraper cannot tell 40 out of 50 from 40 out of 500.
        let s = IndexerStatus::new(1_000);
        s.set_max_reorg_depth(50);
        assert_eq!(s.max_reorg_depth(), 50);
    }

    #[test]
    fn a_fresh_status_is_not_halted() {
        let s = IndexerStatus::new(1_000);
        assert!(!s.is_halted());
        assert_eq!(s.seconds_since_tick(1_000), 0);
    }

    #[test]
    fn a_halt_is_recorded_with_the_depth_that_caused_it() {
        let s = IndexerStatus::new(1_000);
        s.record_halt(120);
        assert!(s.is_halted());
        assert_eq!(s.halted_depth(), 120);
    }

    #[test]
    fn a_halt_is_one_way() {
        // Clearing it means an operator widened max_reorg_depth and
        // restarted; nothing in-process may decide the halt is over.
        let s = IndexerStatus::new(1_000);
        s.record_halt(120);
        s.record_tick(2_000);
        assert!(s.is_halted(), "a later tick must not clear the halt");
    }

    #[test]
    fn ticks_advance_the_freshness_clock() {
        let s = IndexerStatus::new(1_000);
        assert_eq!(s.seconds_since_tick(1_060), 60);
        s.record_tick(1_060);
        assert_eq!(s.seconds_since_tick(1_060), 0);
        assert_eq!(s.seconds_since_tick(1_090), 30);
    }

    #[test]
    fn a_backwards_clock_reports_zero_rather_than_negative_staleness() {
        // A negative value would compare as "very recent" against any
        // threshold, turning a clock problem into a silent monitoring gap.
        let s = IndexerStatus::new(2_000);
        assert_eq!(s.seconds_since_tick(1_000), 0);
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let s = IndexerStatus::new(i64::MIN);
        assert!(s.seconds_since_tick(i64::MAX) >= 0);
    }

    #[test]
    fn the_start_time_seeds_the_clock_so_a_first_scrape_is_not_decades_stale() {
        let s = IndexerStatus::new(1_700_000_000);
        assert_eq!(s.seconds_since_tick(1_700_000_030), 30);
    }
}
