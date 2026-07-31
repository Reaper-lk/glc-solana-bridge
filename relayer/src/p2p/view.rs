//! The validator's own view of the chain, backed by its own database
//! (Phase 7d, ADR-0016).
//!
//! This is the concrete [`LocalView`] the signer server runs on, and it is
//! where the federation's central guarantee actually lands: a signing
//! request is answered from *this* validator's persisted observations, never
//! from anything the requester said.
//!
//! # Derivation goes through the integrity safeguards, on purpose
//!
//! Deriving a deposit message calls
//! [`Db::verify_and_load_signable_message`], and deriving a payout intent
//! calls [`Db::verify_and_load_signable_payout`] — the same
//! reload-and-recompute guards the orchestrator and executor use. So a
//! signer does not merely decline to sign when its persisted state has
//! drifted: it halts that item as an integrity anomaly, exactly as the
//! locally-driven paths do. Reusing the guards, rather than reading the
//! stored bytes directly, is what makes the signer independent instead of a
//! second copy of the requester's trust.
//!
//! # A stale view refuses
//!
//! The observed epoch is polled from the on-chain ValidatorSet. If those
//! polls stop succeeding, the validator cannot distinguish a current epoch
//! from a superseded one, so [`LocalView::view_is_fresh`] goes false and
//! every request is refused until the link recovers. Fail-closed: the
//! process also refuses to start until it has observed the epoch once.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::glc::db::{Db, DepositState};
use crate::glc::withdrawal_db::WithdrawalState;
use crate::p2p::policy::{Action, LocalView, SigningIdentity};

/// How long an epoch observation stays usable without a successful refresh.
///
/// Bounded by how quickly a validator-set rotation must stop a lagging
/// signer from authorizing under the old set. Longer than several poll
/// intervals so a brief RPC blip does not take a signer offline, short
/// enough that a real outage does.
pub const MAX_VIEW_STALENESS: Duration = Duration::from_secs(60);

/// How often the epoch is re-observed from the chain.
pub const EPOCH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The shared, atomically-updated result of epoch polling.
///
/// Separated from [`DbLocalView`] so the refresher task can own a handle
/// without taking the database lock — a signer must never be blocked from
/// noticing a rotation by an in-flight derivation.
#[derive(Debug)]
pub struct EpochObservation {
    epoch: AtomicU64,
    /// Unix seconds of the last *successful* observation. A failed poll
    /// deliberately does not update it — that is what makes staleness
    /// accumulate rather than being papered over.
    observed_at: AtomicI64,
}

impl EpochObservation {
    /// Seeds the observation from a first successful read.
    ///
    /// There is deliberately no constructor producing an *unobserved* state:
    /// a signer with no epoch at all has nothing meaningful to compare
    /// against, so startup blocks on this instead.
    pub fn seeded(epoch: u64, at_unix: i64) -> Self {
        EpochObservation {
            epoch: AtomicU64::new(epoch),
            observed_at: AtomicI64::new(at_unix),
        }
    }

    pub fn record(&self, epoch: u64, at_unix: i64) {
        // Order matters: publish the epoch before the timestamp that
        // vouches for it, so a concurrent reader can never see a fresh
        // timestamp attached to a stale epoch.
        self.epoch.store(epoch, Ordering::SeqCst);
        self.observed_at.store(at_unix, Ordering::SeqCst);
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    pub fn observed_at(&self) -> i64 {
        self.observed_at.load(Ordering::SeqCst)
    }

    pub fn is_fresh_at(&self, now_unix: i64) -> bool {
        let age = now_unix.saturating_sub(self.observed_at());
        // A negative age (clock stepped backwards) is not treated as extra
        // freshness; only a genuinely recent observation counts.
        (0..=MAX_VIEW_STALENESS.as_secs() as i64).contains(&age)
    }
}

/// A [`LocalView`] over this validator's own database.
pub struct DbLocalView {
    /// `Mutex` because `rusqlite::Connection` is `Send` but not `Sync`, and
    /// the gRPC service is shared across tasks. Held only for the duration
    /// of one derivation.
    db: Mutex<Db>,
    epoch: std::sync::Arc<EpochObservation>,
}

impl DbLocalView {
    pub fn new(db: Db, epoch: std::sync::Arc<EpochObservation>) -> Self {
        DbLocalView {
            db: Mutex::new(db),
            epoch,
        }
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Derives the canonical claim message for a deposit this validator has
    /// itself observed and confirmed.
    ///
    /// Returns `None` unless the deposit is in a state where authorizing a
    /// mint is legitimate. `Minted` is excluded along with the terminal
    /// states: the claim PDA already exists, so a fresh signature could only
    /// serve a replay.
    fn derive_deposit(&self, txid: [u8; 32], vout: u32) -> Option<Vec<u8>> {
        let mut db = self.db.lock().ok()?;
        let rows = db.history_for(&txid, vout as i64).ok()?;
        let row = rows.into_iter().find(|r| {
            matches!(
                r.state,
                DepositState::ReadyForSignature | DepositState::Submitted
            )
        })?;
        // The reload-and-recompute safeguard. On drift this halts the
        // deposit as an integrity anomaly rather than returning bytes.
        let claim = db
            .verify_and_load_signable_message(row.id, Self::now_unix())
            .ok()?;
        Some(claim.message.to_vec())
    }

    /// Derives the canonical payout intent for a withdrawal, bound to the
    /// requested quorum attempt.
    ///
    /// The attempt must match what this validator has persisted: ADR-0015
    /// makes a superseded designation a *different* thing to authorize, and
    /// signing for a stale attempt would undermine the deterministic txid
    /// the whole recovery model rests on.
    fn derive_payout(&self, withdrawal_index: u64, quorum_attempt: u32) -> Option<Vec<u8>> {
        let index = i64::try_from(withdrawal_index).ok()?;
        let mut db = self.db.lock().ok()?;

        let w = db.get_withdrawal(index).ok()??;
        if !matches!(
            w.state,
            WithdrawalState::Building | WithdrawalState::Signing
        ) {
            return None;
        }
        let signable = db
            .verify_and_load_signable_payout(index, Self::now_unix())
            .ok()?;
        if signable.quorum_attempt != quorum_attempt {
            tracing::warn!(
                withdrawal_index,
                requested_attempt = quorum_attempt,
                local_attempt = signable.quorum_attempt,
                "refusing a payout attestation for a quorum attempt this validator has not designated"
            );
            return None;
        }
        Some(signable.intent_bytes)
    }
}

impl LocalView for DbLocalView {
    fn observed_epoch(&self) -> u64 {
        self.epoch.epoch()
    }

    fn view_is_fresh(&self) -> bool {
        self.epoch.is_fresh_at(Self::now_unix())
    }

    fn derive_message(&self, action: Action, identity: &SigningIdentity) -> Option<Vec<u8>> {
        match (action, identity) {
            (Action::MintDeposit, SigningIdentity::Deposit { txid, vout }) => {
                self.derive_deposit(*txid, *vout)
            }
            (
                Action::Payout,
                SigningIdentity::Payout {
                    withdrawal_index,
                    quorum_attempt,
                },
            ) => self.derive_payout(*withdrawal_index, *quorum_attempt),
            // Governance signing is not driven from this view (Phase 7a
            // proposals are authorized through the on-chain path), and a
            // mismatched action/identity pair is a protocol error. Both
            // refuse rather than fall through to something plausible.
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_observation_is_usable() {
        let o = EpochObservation::seeded(7, 1_000);
        assert!(o.is_fresh_at(1_000));
        assert!(o.is_fresh_at(1_000 + MAX_VIEW_STALENESS.as_secs() as i64));
        assert_eq!(o.epoch(), 7);
    }

    #[test]
    fn an_observation_goes_stale_once_past_the_bound() {
        let o = EpochObservation::seeded(7, 1_000);
        assert!(
            !o.is_fresh_at(1_001 + MAX_VIEW_STALENESS.as_secs() as i64),
            "a validator that stopped hearing from the chain must stop signing"
        );
    }

    #[test]
    fn a_failed_poll_does_not_refresh_the_observation() {
        // The refresher only calls `record` on success, so staleness
        // accumulates across an outage instead of being papered over.
        let o = EpochObservation::seeded(7, 1_000);
        let far_future = 1_000 + 10 * MAX_VIEW_STALENESS.as_secs() as i64;
        assert!(!o.is_fresh_at(far_future));
        o.record(7, far_future);
        assert!(o.is_fresh_at(far_future), "a successful poll restores it");
    }

    #[test]
    fn an_observation_timestamped_in_the_future_does_not_read_as_fresh() {
        // Both a small and a large backwards step: the small one is the
        // interesting case, because taking the magnitude of the difference
        // would still land inside the staleness bound and silently pass.
        let o = EpochObservation::seeded(7, 1_000);
        assert!(
            !o.is_fresh_at(1_000 - (MAX_VIEW_STALENESS.as_secs() as i64 / 2)),
            "a clock that stepped backwards must not be read as a recent observation"
        );
        assert!(!o.is_fresh_at(500));
    }

    #[test]
    fn a_rotation_is_picked_up_by_the_next_successful_poll() {
        let o = EpochObservation::seeded(7, 1_000);
        o.record(8, 1_005);
        assert_eq!(o.epoch(), 8);
        assert_eq!(o.observed_at(), 1_005);
    }
}
