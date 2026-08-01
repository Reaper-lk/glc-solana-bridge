//! Who acts first when several relayers run at once (Phase 7g, ADR-0019).
//!
//! Leaderless: no election, no distributed lock, no shared state. Assignment
//! is **arithmetic**, and every operator computes the same answer from the
//! same public facts.
//!
//! # Assignment decides who goes first, never who may
//!
//! A designated operator acts immediately; the others wait a timeout and
//! then become eligible too. That keeps liveness when the designated
//! operator is down, at the cost of some duplicated work in the window —
//! which is exactly the trade ADR-0014 §10 intended.
//!
//! # Why payouts need more than this
//!
//! For **mints**, duplication is harmless: the claim PDA's `init` prevents
//! a double-mint (ADR-0003) and only fees are wasted, so assignment here is
//! purely an optimisation.
//!
//! For **payouts** it is not harmless. Phase 7g measured two operators
//! paying the same withdrawal twice (ADR-0019 §2.2), so assignment is
//! paired with builder-authoritative reservation (`payout_view`) and a
//! pre-broadcast on-chain check (`executor`). Assignment alone would only
//! narrow the window, not close it.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssignmentError {
    #[error("operator index {index} is outside a federation of {count}")]
    IndexOutOfRange { index: usize, count: usize },
    #[error("a federation of zero operators cannot assign work")]
    NoOperators,
    #[error("failover timeout must be greater than zero seconds")]
    ZeroTimeout,
}

/// This relayer's place in the federation, and how long it waits before
/// taking over work assigned to somebody else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorAssignment {
    /// This relayer's index, from the vault signer map (ADR-0019 D1).
    pub index: usize,
    /// How many operators the federation has.
    pub count: usize,
    /// Seconds before a non-designated operator may build a payout.
    pub build_timeout_secs: i64,
    /// Seconds before a non-designated operator may submit a mint.
    pub submit_timeout_secs: i64,
}

impl OperatorAssignment {
    pub fn new(
        index: usize,
        count: usize,
        build_timeout_secs: i64,
        submit_timeout_secs: i64,
    ) -> Result<Self, AssignmentError> {
        if count == 0 {
            return Err(AssignmentError::NoOperators);
        }
        if index >= count {
            return Err(AssignmentError::IndexOutOfRange { index, count });
        }
        if build_timeout_secs <= 0 || submit_timeout_secs <= 0 {
            return Err(AssignmentError::ZeroTimeout);
        }
        Ok(OperatorAssignment {
            index,
            count,
            build_timeout_secs,
            submit_timeout_secs,
        })
    }

    /// The operator designated to act first for `work_id`.
    ///
    /// `work_id` is the withdrawal index or deposit id — a value every
    /// operator sees identically, so every operator computes the same
    /// designation without exchanging a message.
    pub fn designated_for(&self, work_id: u64) -> usize {
        (work_id % self.count as u64) as usize
    }

    pub fn is_designated_for(&self, work_id: u64) -> bool {
        self.designated_for(work_id) == self.index
    }

    /// Whether this operator may **build** a payout for `withdrawal_index`
    /// now: either it is designated, or the failover window has elapsed
    /// since the withdrawal was first observed.
    pub fn may_build(&self, withdrawal_index: u64, observed_at: i64, now: i64) -> bool {
        self.is_designated_for(withdrawal_index)
            || now.saturating_sub(observed_at) >= self.build_timeout_secs
    }

    /// Whether this operator may **submit** a mint for `deposit_id` now.
    pub fn may_submit(&self, deposit_id: u64, ready_at: i64, now: i64) -> bool {
        self.is_designated_for(deposit_id)
            || now.saturating_sub(ready_at) >= self.submit_timeout_secs
    }

    /// Whether `proposer` is entitled to propose a payout for
    /// `withdrawal_index` right now (ADR-0019 D3 check 1).
    ///
    /// Used by a passive operator deciding whether to adopt a proposal: a
    /// stranger proposing work assigned to somebody else, before that
    /// somebody has had their window, is refused.
    pub fn may_propose(
        &self,
        proposer: usize,
        withdrawal_index: u64,
        observed_at: i64,
        now: i64,
    ) -> bool {
        self.designated_for(withdrawal_index) == proposer
            || now.saturating_sub(observed_at) >= self.build_timeout_secs
    }
}

/// Designates which M of the vault's N signers sign a payout (ADR-0015).
///
/// Deterministic on the withdrawal index so every operator derives the same
/// designation without negotiating. Shared by the executor (which proposes)
/// and `p2p::payout_view` (which adopts a proposal) so the two cannot come
/// to disagree — a divergence there would be invisible until a payout
/// failed to reach threshold.
pub fn designate_quorum(index: i64, signer_count: usize, threshold: usize) -> Vec<u8> {
    let start = (index.unsigned_abs() as usize) % signer_count;
    let mut picked: Vec<u8> = (0..threshold)
        .map(|k| ((start + k) % signer_count) as u8)
        .collect();
    // Ascending order is part of the canonical encoding, so a quorum has
    // exactly one representation.
    picked.sort_unstable();
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(index: usize) -> OperatorAssignment {
        OperatorAssignment::new(index, 3, 60, 30).unwrap()
    }

    #[test]
    fn every_operator_computes_the_same_designation() {
        // The load-bearing property: no messages are exchanged, so all
        // operators must agree by arithmetic alone.
        for work in 0..30u64 {
            let seen: Vec<usize> = (0..3).map(|i| a(i).designated_for(work)).collect();
            assert!(
                seen.windows(2).all(|w| w[0] == w[1]),
                "work {work} designated inconsistently: {seen:?}"
            );
        }
    }

    #[test]
    fn designation_spreads_work_across_operators() {
        let counts = (0..30u64)
            .map(|w| a(0).designated_for(w))
            .fold([0usize; 3], |mut acc, d| {
                acc[d] += 1;
                acc
            });
        assert_eq!(counts, [10, 10, 10], "work must be evenly assigned");
    }

    #[test]
    fn exactly_one_operator_is_designated_for_any_work_item() {
        for work in 0..30u64 {
            let n = (0..3).filter(|i| a(*i).is_designated_for(work)).count();
            assert_eq!(n, 1, "work {work} had {n} designated operators");
        }
    }

    #[test]
    fn the_designated_operator_may_act_immediately() {
        let op = a(1);
        assert!(op.is_designated_for(1));
        assert!(op.may_build(1, 1_000, 1_000), "no waiting when designated");
    }

    #[test]
    fn a_non_designated_operator_waits_for_the_failover_window() {
        let op = a(0);
        assert!(!op.is_designated_for(1), "operator 1 is designated for 1");
        assert!(!op.may_build(1, 1_000, 1_000), "must not act immediately");
        assert!(!op.may_build(1, 1_000, 1_059), "must wait the full window");
        assert!(op.may_build(1, 1_000, 1_060), "and then may take over");
    }

    #[test]
    fn failover_keeps_liveness_when_the_designated_operator_is_down() {
        // Every other operator eventually becomes eligible, so one dead
        // operator cannot strand a withdrawal forever.
        for i in [0usize, 2] {
            assert!(a(i).may_build(1, 1_000, 1_060), "operator {i} takes over");
        }
    }

    #[test]
    fn mints_and_payouts_have_independent_failover_windows() {
        // Mint duplication is harmless, payout duplication is not, so the
        // two windows are configured separately.
        let op = a(0);
        assert!(!op.may_build(1, 1_000, 1_040), "build window is 60s");
        assert!(op.may_submit(1, 1_000, 1_040), "submit window is 30s");
    }

    #[test]
    fn a_stranger_may_not_propose_work_assigned_to_someone_else() {
        // ADR-0019 D3 check 1: a passive operator refuses a proposal from an
        // operator that has no business making it yet.
        let me = a(2);
        // Withdrawal 1 is designated to operator 1.
        assert!(me.may_propose(1, 1, 1_000, 1_000), "the designated one may");
        assert!(
            !me.may_propose(0, 1, 1_000, 1_000),
            "operator 0 may not, before the window"
        );
        assert!(
            me.may_propose(0, 1, 1_000, 1_060),
            "but may once the window has elapsed"
        );
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_grant_early_failover() {
        let op = a(0);
        assert!(
            !op.may_build(1, 2_000, 1_000),
            "a withdrawal observed in the future must not look overdue"
        );
    }

    #[test]
    fn quorum_designation_is_deterministic_and_canonical() {
        for index in 0..20i64 {
            let a = designate_quorum(index, 3, 2);
            assert_eq!(a, designate_quorum(index, 3, 2), "same input, same output");
            assert_eq!(a.len(), 2, "exactly threshold-many signers");
            let mut sorted = a.clone();
            sorted.sort_unstable();
            assert_eq!(a, sorted, "ascending is the canonical form");
            assert!(a.iter().all(|i| (*i as usize) < 3), "in range");
            assert_ne!(a[0], a[1], "distinct signers");
        }
    }

    #[test]
    fn quorum_designation_spreads_across_signers() {
        let starts: std::collections::HashSet<u8> =
            (0..3i64).map(|i| designate_quorum(i, 3, 2)[0]).collect();
        assert!(starts.len() > 1, "not always the same signers");
    }

    #[test]
    fn rejects_a_nonsensical_configuration() {
        assert_eq!(
            OperatorAssignment::new(0, 0, 60, 30).unwrap_err(),
            AssignmentError::NoOperators
        );
        assert_eq!(
            OperatorAssignment::new(3, 3, 60, 30).unwrap_err(),
            AssignmentError::IndexOutOfRange { index: 3, count: 3 }
        );
        assert_eq!(
            OperatorAssignment::new(0, 3, 0, 30).unwrap_err(),
            AssignmentError::ZeroTimeout
        );
        assert_eq!(
            OperatorAssignment::new(0, 3, 60, 0).unwrap_err(),
            AssignmentError::ZeroTimeout
        );
    }

    #[test]
    fn a_single_operator_federation_is_always_designated() {
        // The degenerate but real case: one operator must never wait for
        // itself.
        let solo = OperatorAssignment::new(0, 1, 60, 30).unwrap();
        for work in 0..10u64 {
            assert!(solo.is_designated_for(work));
            assert!(solo.may_build(work, 1_000, 1_000));
        }
    }
}
