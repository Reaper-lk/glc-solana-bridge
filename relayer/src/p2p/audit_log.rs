//! The record a validator leaves when it **grants** a signature
//! (ADR-0014 §13.3).
//!
//! # The asymmetry this fixes
//!
//! Every signing path logged its **refusals** loudly from the day it was
//! written, because a refusal means this validator's view disagrees with a
//! peer's — an alarm. But three of the five paths logged nothing at all when
//! they *granted*, so the exercise of a validator's authority left no local
//! trace.
//!
//! That is backwards for forensics. After an incident the question is rarely
//! "what did we refuse"; it is "what did we authorise, and when". Refusals
//! are recoverable from the peer that was refused. A grant, once the
//! signature has been aggregated into someone else's transaction, is
//! recoverable only from the chain — and never at all if the question is
//! whether *this signer* was induced to sign something it should not have.
//!
//! # What this is, and what it is not
//!
//! It is a **structured log event**, not a database row. ADR-0014 §13.3
//! describes the audit trail as "append-only, shipped off-host", which is a
//! log-shipping model; the state-transition tables it names alongside exist
//! because those record *state*, and a signature decision is an *event*.
//!
//! The honest cost: **a log lost before it is shipped is gone.** Shipping is
//! the operator's responsibility and is an open item on the launch checklist
//! (§13.3). Writing a row instead would survive log loss, at the price of a
//! database write on every signature — on a path where `Db` is `Send` but not
//! `Sync`, and where the signer deliberately does as little as possible.
//! That trade is recorded here rather than left to be rediscovered.
//!
//! # What is deliberately not recorded
//!
//! - **The signature bytes.** The authoritative copy lives on chain or in
//!   the assembled transaction; a second copy in a log invites someone to
//!   treat the log as the source of truth.
//! - **The canonical message.** The identity below determines it, and
//!   logging a few hundred bytes per signature buries the field that matters.
//! - **Key material**, obviously — no path here has access to any.

use tracing::{info, warn};

/// What was authorised. Each variant carries exactly enough to identify the
/// thing signed, so an auditor can line the record up against the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granted<'a> {
    /// A deposit mint, keyed by its Goldcoin outpoint (ADR-0002).
    Mint { txid: &'a [u8; 32], vout: u32 },
    /// A vault payout, keyed by withdrawal index and quorum attempt — a
    /// superseded designation is a different authorisation (ADR-0015).
    Payout {
        withdrawal_index: u64,
        quorum_attempt: u32,
    },
    /// An attestation that a withdrawal was paid.
    Completion {
        withdrawal_index: u64,
        payout_txid: &'a [u8; 32],
    },
    /// A governance action. Changes federation policy.
    Governance { action: u8, epoch: u64 },
    /// A vault sweep. Moves the entire vault.
    Sweep { inputs: usize, swept_atomic: u64 },
}

impl Granted<'_> {
    /// The action name, stable and greppable.
    pub fn action(&self) -> &'static str {
        match self {
            Granted::Mint { .. } => "mint",
            Granted::Payout { .. } => "payout",
            Granted::Completion { .. } => "completion",
            Granted::Governance { .. } => "governance",
            Granted::Sweep { .. } => "sweep",
        }
    }

    /// Whether this authorisation is one an operator should see even when
    /// they are not looking for it.
    ///
    /// Mints, payouts and completions are the bridge doing its job, many
    /// times an hour. Governance changes who the federation *is*, and a
    /// sweep moves every coin the vault holds — neither is routine, and
    /// neither should be filtered out by a level that hides ordinary traffic.
    pub fn is_notable(&self) -> bool {
        matches!(self, Granted::Governance { .. } | Granted::Sweep { .. })
    }

    /// The identity of the thing signed, rendered for the log.
    pub fn identity(&self) -> String {
        match self {
            Granted::Mint { txid, vout } => {
                format!("{}:{vout}", crate::glc::hex::encode(*txid))
            }
            Granted::Payout {
                withdrawal_index,
                quorum_attempt,
            } => format!("withdrawal {withdrawal_index} attempt {quorum_attempt}"),
            Granted::Completion {
                withdrawal_index,
                payout_txid,
            } => format!(
                "withdrawal {withdrawal_index} paid by {}",
                crate::glc::hex::encode(*payout_txid)
            ),
            Granted::Governance { action, epoch } => {
                format!("action {action} under epoch {epoch}")
            }
            Granted::Sweep {
                inputs,
                swept_atomic,
            } => format!("{inputs} inputs totalling {swept_atomic} atomic"),
        }
    }
}

/// The event name every grant carries, so one grep finds all of them across
/// every host in the federation.
pub const EVENT: &str = "signature_granted";

/// Records that this validator granted a signature.
///
/// Called at the **decision point**, not in the transport layer, so a grant
/// is recorded however the service was driven — the transport's own peer
/// logging sits alongside it and answers a different question ("who asked").
pub fn record(granted: Granted<'_>, validator: &[u8; 32]) {
    let validator = crate::glc::hex::encode(validator);
    let action = granted.action();
    let identity = granted.identity();
    if granted.is_notable() {
        warn!(
            event = EVENT,
            action,
            %identity,
            %validator,
            "GRANTED a signature that changes federation policy or moves the vault"
        );
    } else {
        info!(
            event = EVENT,
            action,
            %identity,
            %validator,
            "granted a signature"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_has_a_stable_greppable_name() {
        // The names end up in log-shipping filters and alert rules. Changing
        // one silently breaks whatever an operator built on it.
        assert_eq!(
            Granted::Mint {
                txid: &[0; 32],
                vout: 0
            }
            .action(),
            "mint"
        );
        assert_eq!(
            Granted::Payout {
                withdrawal_index: 1,
                quorum_attempt: 0
            }
            .action(),
            "payout"
        );
        assert_eq!(
            Granted::Completion {
                withdrawal_index: 1,
                payout_txid: &[0; 32]
            }
            .action(),
            "completion"
        );
        assert_eq!(
            Granted::Governance {
                action: 3,
                epoch: 1
            }
            .action(),
            "governance"
        );
        assert_eq!(
            Granted::Sweep {
                inputs: 1,
                swept_atomic: 1
            }
            .action(),
            "sweep"
        );
        assert_eq!(EVENT, "signature_granted");
    }

    #[test]
    fn only_governance_and_sweep_are_notable() {
        // Mints and payouts happen many times an hour; governance changes
        // who the federation is and a sweep moves every coin.
        assert!(Granted::Governance {
            action: 3,
            epoch: 1
        }
        .is_notable());
        assert!(Granted::Sweep {
            inputs: 1,
            swept_atomic: 1
        }
        .is_notable());
        assert!(!Granted::Mint {
            txid: &[0; 32],
            vout: 0
        }
        .is_notable());
        assert!(!Granted::Payout {
            withdrawal_index: 1,
            quorum_attempt: 0
        }
        .is_notable());
        assert!(!Granted::Completion {
            withdrawal_index: 1,
            payout_txid: &[0; 32]
        }
        .is_notable());
    }

    #[test]
    fn a_mint_identity_is_the_outpoint_an_auditor_can_look_up() {
        let g = Granted::Mint {
            txid: &[0xAB; 32],
            vout: 3,
        };
        let id = g.identity();
        assert!(id.ends_with(":3"), "{id}");
        assert!(id.starts_with("abab"), "{id}");
    }

    #[test]
    fn a_payout_identity_distinguishes_quorum_attempts() {
        // Attempt 0 and attempt 1 are different authorisations over
        // different bytes (ADR-0015); a record that conflated them would be
        // useless in exactly the incident it exists for.
        let a = Granted::Payout {
            withdrawal_index: 7,
            quorum_attempt: 0,
        }
        .identity();
        let b = Granted::Payout {
            withdrawal_index: 7,
            quorum_attempt: 1,
        }
        .identity();
        assert_ne!(a, b);
    }

    #[test]
    fn a_completion_identity_names_the_paying_transaction() {
        let g = Granted::Completion {
            withdrawal_index: 4,
            payout_txid: &[0xCD; 32],
        };
        let id = g.identity();
        assert!(id.contains('4'), "{id}");
        assert!(id.contains("cdcd"), "{id}");
    }

    #[test]
    fn a_governance_identity_carries_both_the_action_and_the_epoch() {
        // A governance signature is bound to the epoch it was made under; a
        // record naming only the action could not tell two apart.
        let a = Granted::Governance {
            action: 3,
            epoch: 1,
        }
        .identity();
        let b = Granted::Governance {
            action: 3,
            epoch: 2,
        }
        .identity();
        assert_ne!(a, b);
    }

    #[test]
    fn a_sweep_identity_states_what_left_the_vault() {
        let id = Granted::Sweep {
            inputs: 3,
            swept_atomic: 12_000_000_000,
        }
        .identity();
        assert!(id.contains('3'), "{id}");
        assert!(id.contains("12000000000"), "{id}");
    }
}
