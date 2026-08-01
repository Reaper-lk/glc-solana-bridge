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

use std::sync::Mutex;

use crate::glc::db::{Db, DepositState};
use crate::glc::withdrawal_db::WithdrawalState;
use crate::p2p::policy::{Action, LocalView, SigningIdentity};

// The epoch observation lives in `solana::epoch` so `signer-server` and
// `glc-relayer` cannot come to disagree about what "stale" means. Re-exported
// here because this is where it is consumed.
pub use crate::solana::epoch::{EpochObservation, EPOCH_POLL_INTERVAL, MAX_VIEW_STALENESS};

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
    // `EpochObservation`'s own behaviour is tested at its home in
    // `solana::epoch`; `DbLocalView` is covered end-to-end against a real
    // database in `tests/signer_local_view.rs`.
    use super::*;

    #[test]
    fn re_exports_the_shared_epoch_observation() {
        let o = EpochObservation::seeded(7, 1_000);
        assert_eq!(o.epoch(), 7);
        assert!(o.is_fresh_at(1_000));
    }
}
