//! The solvency invariant, and the fee drift that is NOT part of it
//! (Phase 7h, ADR-0014 §13.1 / ADR-0020).
//!
//! # The invariant this asserts
//!
//! Threat-model invariant #1:
//!
//! ```text
//! wrapped_supply <= confirmed_deposits - completed_payouts
//! ```
//!
//! Measured on regtest, this holds with **exactly zero slack** at every
//! point — each burn reduces supply by precisely the amount later paid out.
//! That is what makes it a good alarm: there is no normal drift to tune a
//! threshold against, so *any* positive breach is real and immediate.
//!
//! # The fee drift this deliberately does NOT treat as insolvency
//!
//! ADR-0013 D3 makes the vault absorb the payout fee: the user receives
//! exactly the burned amount, and the fee comes out of the vault's own
//! inputs. So every payout removes `amount + fee` from the vault while
//! supply falls by only `amount`.
//!
//! Measured over four real payouts, the gap between the invariant's bound
//! and the vault's actual balance equalled the cumulative fees **exactly**.
//! The bridge is therefore fractionally under-backed by an amount that grows
//! with payout count, and nothing in the protocol replenishes it.
//!
//! Owner decision (ADR-0020): this is an **operational** quantity, not a
//! solvency failure. Operators replenish the vault from an external fee
//! reserve. It is reported separately — visible, bounded and auditable —
//! rather than folded into the invariant, where it would make the alarm
//! permanently red and therefore useless.
//!
//! The two are computed and exposed independently so a later move to a
//! protocol-level fee model changes the drift term and leaves the invariant
//! untouched.

use crate::glc::db::{Db, DbError};

/// Everything a solvency check needs, gathered from one relayer's own view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolvencySnapshot {
    /// Wrapped-GLC supply reported by the SPL mint on Solana.
    pub wrapped_supply: u64,
    /// Total confirmed deposits this relayer has seen minted.
    pub confirmed_deposits: u64,
    /// Total paid out to users (burned amounts, excluding fees — ADR-0013
    /// D3 means these are exactly the burned amounts).
    pub completed_payouts: u64,
    /// Cumulative Goldcoin fees the vault has absorbed.
    pub vault_fees_paid: u64,
    /// The vault's confirmed on-chain balance, or `None` when it could not
    /// be read this cycle.
    pub vault_balance: Option<u64>,
}

impl SolvencySnapshot {
    /// The invariant's upper bound on wrapped supply.
    ///
    /// Saturating rather than checked: payouts can briefly exceed observed
    /// deposits on a relayer that is still catching up on deposit history,
    /// and a monitor must report that as a breach rather than panic on it.
    pub fn backing_bound(&self) -> u64 {
        self.confirmed_deposits
            .saturating_sub(self.completed_payouts)
    }

    /// Whether threat-model invariant #1 holds.
    pub fn invariant_holds(&self) -> bool {
        self.wrapped_supply <= self.backing_bound()
    }

    /// How far the invariant is breached, in atomic units. Zero when it
    /// holds.
    ///
    /// This is the number that must be zero. Any positive value means more
    /// wrapped GLC exists than deposits minus payouts can account for.
    pub fn breach_atomic(&self) -> u64 {
        self.wrapped_supply.saturating_sub(self.backing_bound())
    }

    /// The vault's shortfall against the invariant's bound — the ADR-0013 D3
    /// fee drift.
    ///
    /// Expected to equal `vault_fees_paid` and to grow with payout count.
    /// **Not** a solvency failure (ADR-0020): it is the operational quantity
    /// an external fee reserve replenishes.
    pub fn fee_drift_atomic(&self) -> Option<u64> {
        self.vault_balance
            .map(|bal| self.backing_bound().saturating_sub(bal))
    }

    /// Whether the observed drift is explained by fees the vault is known to
    /// have paid.
    ///
    /// Drift **beyond** the fees this relayer recorded is a different thing
    /// entirely — value has left the vault that no payout of ours accounts
    /// for — and is worth alarming on even though ordinary drift is not.
    pub fn drift_is_explained_by_fees(&self) -> Option<bool> {
        self.fee_drift_atomic().map(|d| d <= self.vault_fees_paid)
    }

    /// Drift that fees do NOT explain. Zero when everything is accounted
    /// for.
    pub fn unexplained_drift_atomic(&self) -> Option<u64> {
        self.fee_drift_atomic()
            .map(|d| d.saturating_sub(self.vault_fees_paid))
    }
}

/// The database half of a snapshot. The chain-side quantities
/// (`wrapped_supply`, `vault_balance`) are supplied by the caller, which is
/// what keeps this function pure and testable.
pub fn snapshot_from_db(
    db: &Db,
    wrapped_supply: u64,
    vault_balance: Option<u64>,
) -> Result<SolvencySnapshot, DbError> {
    Ok(SolvencySnapshot {
        wrapped_supply,
        confirmed_deposits: db.minted_deposit_total()?,
        completed_payouts: db.completed_payout_total()?,
        vault_fees_paid: db.vault_fees_paid_total()?,
        vault_balance,
    })
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

    #[test]
    fn the_invariant_holds_with_exactly_zero_slack_in_the_normal_case() {
        // Measured behaviour: each burn reduces supply by precisely the
        // amount later paid out, so the bound is met exactly. That is why
        // any positive breach is meaningful rather than noise.
        let s = snap(
            21_000_000_000,
            25_000_000_000,
            4_000_000_000,
            0,
            Some(21_000_000_000),
        );
        assert!(s.invariant_holds());
        assert_eq!(s.breach_atomic(), 0);
        assert_eq!(
            s.backing_bound(),
            21_000_000_000,
            "bound == supply, zero slack"
        );
    }

    #[test]
    fn one_atom_of_excess_supply_is_a_breach() {
        let s = snap(
            21_000_000_001,
            25_000_000_000,
            4_000_000_000,
            0,
            Some(21_000_000_000),
        );
        assert!(!s.invariant_holds());
        assert_eq!(s.breach_atomic(), 1);
    }

    #[test]
    fn fee_drift_is_reported_but_is_not_a_breach() {
        // The measured shape: vault balance below the bound by exactly the
        // fees paid. The invariant must still hold — treating this as
        // insolvency would leave the alarm permanently red.
        let s = snap(
            21_000_000_000,
            25_000_000_000,
            4_000_000_000,
            904,
            Some(20_999_999_096),
        );
        assert!(
            s.invariant_holds(),
            "fee drift must never make the invariant fail"
        );
        assert_eq!(s.breach_atomic(), 0);
    }

    #[test]
    fn drift_equal_to_the_fees_paid_is_fully_explained() {
        let s = snap(
            21_000_000_000,
            25_000_000_000,
            4_000_000_000,
            904,
            Some(20_999_999_096),
        );
        assert_eq!(s.fee_drift_atomic(), Some(904));
        assert_eq!(s.drift_is_explained_by_fees(), Some(true));
        assert_eq!(s.unexplained_drift_atomic(), Some(0));
    }

    #[test]
    fn drift_beyond_the_fees_paid_is_flagged_separately() {
        // Value left the vault that no payout of ours accounts for. Ordinary
        // drift is expected; this is not, and the two must not be conflated.
        let s = snap(
            21_000_000_000,
            25_000_000_000,
            4_000_000_000,
            904,
            Some(20_999_990_000),
        );
        assert_eq!(s.fee_drift_atomic(), Some(10_000));
        assert_eq!(s.drift_is_explained_by_fees(), Some(false));
        assert_eq!(s.unexplained_drift_atomic(), Some(9_096));
        assert!(
            s.invariant_holds(),
            "still not a solvency breach — a DIFFERENT alarm"
        );
    }

    #[test]
    fn a_vault_richer_than_the_bound_reports_no_drift() {
        // After an operator tops the vault up from the fee reserve, the
        // balance can exceed the bound. That is the reserve working, not a
        // negative deficit, so drift saturates at zero.
        let s = snap(
            21_000_000_000,
            25_000_000_000,
            4_000_000_000,
            904,
            Some(30_000_000_000),
        );
        assert_eq!(s.fee_drift_atomic(), Some(0));
        assert_eq!(s.unexplained_drift_atomic(), Some(0));
        assert_eq!(s.drift_is_explained_by_fees(), Some(true));
    }

    #[test]
    fn an_unreadable_vault_reports_no_drift_rather_than_a_wrong_one() {
        // A missing reading must not be silently rendered as zero drift by
        // the caller; it is absent, and the metric is simply not exported.
        let s = snap(21_000_000_000, 25_000_000_000, 4_000_000_000, 904, None);
        assert_eq!(s.fee_drift_atomic(), None);
        assert_eq!(s.drift_is_explained_by_fees(), None);
        assert!(
            s.invariant_holds(),
            "the invariant does not depend on the vault reading at all"
        );
    }

    #[test]
    fn payouts_exceeding_observed_deposits_report_a_breach_rather_than_panicking() {
        // A relayer still catching up on deposit history can transiently see
        // more payouts than deposits. It must report, not overflow.
        let s = snap(10, 40, 100, 0, Some(0));
        assert_eq!(s.backing_bound(), 0);
        assert!(!s.invariant_holds());
        assert_eq!(s.breach_atomic(), 10);
    }

    #[test]
    fn a_bridge_with_nothing_in_it_is_solvent() {
        let s = snap(0, 0, 0, 0, Some(0));
        assert!(s.invariant_holds());
        assert_eq!(s.breach_atomic(), 0);
        assert_eq!(s.unexplained_drift_atomic(), Some(0));
    }
}
