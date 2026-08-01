//! The checks `glc-admin` makes before it submits anything (Phase 7i-1).
//!
//! Pure and I/O-free, for the same reason `p2p::policy` is: these decide
//! whether an irreversible on-chain action goes ahead, and logic that can
//! only be reached by standing up a cluster is logic nothing tests.
//!
//! # These are not the security boundary
//!
//! Every one of them is also enforced on-chain: the program re-checks the
//! timelock, refuses the wrong handler for a queued action, and verifies the
//! federation proof itself. Nothing here can authorise something the program
//! would refuse.
//!
//! What they buy is **a clear refusal instead of an obscure one**. An
//! operator who runs `execute-rotation` four minutes early should be told
//! "236 seconds remain", not handed a base58 transaction signature and a
//! program error code to decode — at 3am, during an incident, from a
//! terminal. That is worth testing properly.

use thiserror::Error;

use crate::solana::rpc::PendingActionSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreflightRefusal {
    #[error(
        "only {collected} of {threshold} operators have approved this proposal — nothing was \
         submitted"
    )]
    NotEnoughApprovals { collected: usize, threshold: u8 },
    #[error("there is no pending governance action")]
    NothingPending,
    #[error(
        "a governance action is already pending — execute or cancel it first (the pending-action \
         account is a singleton)"
    )]
    AlreadyPending,
    #[error("the pending action is {found} but this command executes {expected}")]
    WrongActionType { expected: u8, found: u8 },
    #[error("the governance timelock has not elapsed: {remaining} seconds remain (eta {eta})")]
    TimelockNotElapsed { remaining: i64, eta: i64 },
    #[error("the proposal was made under epoch {proposed}, the federation is now at {observed}")]
    EpochMoved { proposed: u64, observed: u64 },
}

/// Whether enough operators independently approved.
///
/// Counted from **unique** signers upstream (`Round::unique_signers`), never
/// from the number of responses: one peer answering twice must never look
/// like two approvals.
pub fn enough_approvals(collected: usize, threshold: u8) -> Result<(), PreflightRefusal> {
    if collected < usize::from(threshold) {
        return Err(PreflightRefusal::NotEnoughApprovals {
            collected,
            threshold,
        });
    }
    Ok(())
}

/// Whether a *new* proposal can be queued.
///
/// The pending-action account is a singleton, so a second proposal fails
/// on-chain with an account-already-initialized error that says nothing
/// about governance. Catching it here explains what to do instead.
pub fn can_propose(pending: Option<&PendingActionSnapshot>) -> Result<(), PreflightRefusal> {
    match pending {
        Some(_) => Err(PreflightRefusal::AlreadyPending),
        None => Ok(()),
    }
}

/// Whether a queued action can be executed **now**, by the command the
/// operator actually ran.
///
/// `observed_epoch` is the federation this operator currently sees. A
/// proposal approved under one federation must never be applied by another
/// — the program enforces this too, but an operator who has just completed a
/// rotation and is now trying to execute a stale cap raise deserves to be
/// told why rather than shown a failed transaction.
pub fn can_execute(
    pending: Option<&PendingActionSnapshot>,
    expected_action: u8,
    observed_epoch: u64,
    now_unix: i64,
) -> Result<(), PreflightRefusal> {
    let p = pending.ok_or(PreflightRefusal::NothingPending)?;
    if p.action != expected_action {
        return Err(PreflightRefusal::WrongActionType {
            expected: expected_action,
            found: p.action,
        });
    }
    if p.proposed_under_epoch != observed_epoch {
        return Err(PreflightRefusal::EpochMoved {
            proposed: p.proposed_under_epoch,
            observed: observed_epoch,
        });
    }
    if now_unix < p.eta {
        return Err(PreflightRefusal::TimelockNotElapsed {
            // Saturating: an `eta` far in the future must not wrap into a
            // negative "remaining" that reads as elapsed.
            remaining: p.eta.saturating_sub(now_unix),
            eta: p.eta,
        });
    }
    Ok(())
}

/// The action a cancellation must commit to, read from the chain.
///
/// Returned as a pair rather than left to the caller because
/// `shared::governance::cancel_params` commits to **both**, and a cancel
/// proof built from a remembered eta is one the program rejects after the
/// entire federation has been asked to sign it.
pub fn cancel_target(
    pending: Option<&PendingActionSnapshot>,
) -> Result<(u8, i64), PreflightRefusal> {
    let p = pending.ok_or(PreflightRefusal::NothingPending)?;
    Ok((p.action, p.eta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;

    const ROTATION: u8 = 0x03;
    const TVL_RAISE: u8 = 0x05;

    fn pending(action: u8, epoch: u64, eta: i64) -> PendingActionSnapshot {
        PendingActionSnapshot {
            action,
            proposed_under_epoch: epoch,
            eta,
            threshold: 2,
            validators: vec![Pubkey::new_unique()],
            proposed_max_wrapped_supply: 0,
        }
    }

    // --- approvals -------------------------------------------------------

    #[test]
    fn the_exact_threshold_is_enough_and_one_short_is_not() {
        assert!(enough_approvals(2, 2).is_ok());
        assert!(enough_approvals(3, 2).is_ok(), "more than enough is fine");
        assert_eq!(
            enough_approvals(1, 2).unwrap_err(),
            PreflightRefusal::NotEnoughApprovals {
                collected: 1,
                threshold: 2
            }
        );
    }

    #[test]
    fn zero_approvals_never_suffice_for_a_real_threshold() {
        assert!(enough_approvals(0, 1).is_err());
        assert!(enough_approvals(0, 255).is_err());
    }

    // --- proposing -------------------------------------------------------

    #[test]
    fn a_proposal_is_refused_while_another_is_pending() {
        // The account is a singleton; the on-chain failure says nothing
        // about governance, so this explains it instead.
        assert_eq!(
            can_propose(Some(&pending(ROTATION, 1, 0))).unwrap_err(),
            PreflightRefusal::AlreadyPending
        );
        assert!(can_propose(None).is_ok());
    }

    // --- executing -------------------------------------------------------

    #[test]
    fn executing_with_nothing_pending_is_refused() {
        assert_eq!(
            can_execute(None, ROTATION, 1, 0).unwrap_err(),
            PreflightRefusal::NothingPending
        );
    }

    #[test]
    fn the_wrong_execute_command_is_refused_by_action_type() {
        // Executing a queued cap raise with the rotation command would fail
        // on-chain; here the operator is told which command they want.
        let p = pending(TVL_RAISE, 1, 0);
        assert_eq!(
            can_execute(Some(&p), ROTATION, 1, 100).unwrap_err(),
            PreflightRefusal::WrongActionType {
                expected: ROTATION,
                found: TVL_RAISE
            }
        );
        assert!(can_execute(Some(&p), TVL_RAISE, 1, 100).is_ok());
    }

    #[test]
    fn a_proposal_from_a_superseded_federation_is_refused() {
        // A rotation that has already been applied moves the epoch; a stale
        // proposal queued under the old one must not be executed.
        let p = pending(ROTATION, 7, 0);
        assert_eq!(
            can_execute(Some(&p), ROTATION, 8, 100).unwrap_err(),
            PreflightRefusal::EpochMoved {
                proposed: 7,
                observed: 8
            }
        );
    }

    #[test]
    fn the_timelock_boundary_is_inclusive_at_the_eta() {
        // eta is the EARLIEST permitted time, so eta itself executes.
        let p = pending(ROTATION, 1, 1_000);
        assert!(can_execute(Some(&p), ROTATION, 1, 1_000).is_ok());
        assert!(can_execute(Some(&p), ROTATION, 1, 1_001).is_ok());
        assert_eq!(
            can_execute(Some(&p), ROTATION, 1, 999).unwrap_err(),
            PreflightRefusal::TimelockNotElapsed {
                remaining: 1,
                eta: 1_000
            }
        );
    }

    #[test]
    fn the_remaining_time_reported_is_the_real_wait() {
        let p = pending(ROTATION, 1, 1_000);
        assert_eq!(
            can_execute(Some(&p), ROTATION, 1, 764).unwrap_err(),
            PreflightRefusal::TimelockNotElapsed {
                remaining: 236,
                eta: 1_000
            }
        );
    }

    #[test]
    fn a_far_future_eta_does_not_wrap_into_looking_elapsed() {
        // i64::MAX - i64::MIN overflows; saturating subtraction keeps the
        // refusal a refusal rather than turning it into a huge negative
        // "remaining" that a naive comparison would read as ready.
        let p = pending(ROTATION, 1, i64::MAX);
        let err = can_execute(Some(&p), ROTATION, 1, i64::MIN).unwrap_err();
        assert!(
            matches!(
                err,
                PreflightRefusal::TimelockNotElapsed { remaining, .. } if remaining > 0
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn the_action_type_is_checked_before_the_timelock() {
        // Otherwise an operator running the wrong command against a
        // not-yet-ready action would be told to wait, then told it was the
        // wrong command — two round trips for one mistake.
        let p = pending(TVL_RAISE, 1, 9_999);
        assert!(matches!(
            can_execute(Some(&p), ROTATION, 1, 0).unwrap_err(),
            PreflightRefusal::WrongActionType { .. }
        ));
    }

    // --- cancelling ------------------------------------------------------

    #[test]
    fn a_cancellation_targets_the_action_and_eta_actually_on_chain() {
        // Both go into `cancel_params`, and a remembered eta produces a
        // proof the program rejects after everyone has signed it.
        let p = pending(TVL_RAISE, 3, 1_234_567);
        assert_eq!(cancel_target(Some(&p)).unwrap(), (TVL_RAISE, 1_234_567));
    }

    #[test]
    fn there_is_nothing_to_cancel_when_nothing_is_pending() {
        assert_eq!(
            cancel_target(None).unwrap_err(),
            PreflightRefusal::NothingPending
        );
    }
}
