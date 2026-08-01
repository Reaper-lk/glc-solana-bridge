//! What a validator will attest a withdrawal completion for (Phase 7f,
//! ADR-0018 D6).
//!
//! Completion is **terminal and irreversible on-chain**, so this is the most
//! consequential signature the federation produces: once M validators
//! attest, the withdrawal is permanently marked paid and no instruction can
//! undo it.
//!
//! # What a signer independently checks
//!
//! A validator signs only when **its own** Goldcoin node confirms that the
//! named payout:
//!
//! 1. exists and is confirmed at or beyond the configured withdrawal
//!    confirmation depth (owner decision Q2: the **same** depth that governs
//!    treating a payout as confirmed locally — one policy, so an operator
//!    cannot complete on-chain something they do not consider confirmed);
//! 2. is the payout **this validator itself** recorded for that withdrawal;
//! 3. is at the height the requester claims.
//!
//! The requester's assertion is compared, never adopted — the same
//! discipline as `payout_view` (ADR-0017 D3) and `view` (ADR-0016).
//!
//! # Why the amount and destination are in the message
//!
//! They are precisely the facts a signer can check against the chain. A
//! message saying only "withdrawal N is finished" would ask a validator to
//! attest to something it has no way to verify.

use thiserror::Error;

use crate::glc::db::Db;
use crate::glc::withdrawal_db::WithdrawalState;
use crate::withdrawal::executor::{PayoutRpc, TxStatus};

/// Why a completion attestation was refused.
///
/// Every variant is an **alarm**: this validator's view of the Goldcoin
/// chain disagrees with a peer's about a payment that is about to be
/// declared final.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompletionRefusal {
    #[error("this validator has no record of withdrawal {0}")]
    UnknownWithdrawal(u64),
    #[error(
        "withdrawal {index} is in state {state} — this validator has not itself completed it and \
         will not attest that anyone else has"
    )]
    NotLocallyCompleted { index: u64, state: String },
    #[error("this validator has no payout record for withdrawal {0}")]
    NoPayout(u64),
    #[error(
        "requester names payout {requested}, this validator paid {local} — refusing to attest a \
         payout it did not make"
    )]
    TxidMismatch { requested: String, local: String },
    #[error(
        "requester claims height {requested}, this validator observes {local} for that payout"
    )]
    HeightMismatch { requested: u64, local: u64 },
    #[error(
        "payout for withdrawal {index} has {confirmations} confirmations, below the required \
         depth of {required} — refusing to attest a payment that could still be reorged out"
    )]
    InsufficientConfirmations {
        index: u64,
        confirmations: i64,
        required: i64,
    },
    #[error("this validator's Goldcoin node does not know payout {0}")]
    PayoutUnknownToNode(String),
    #[error("Goldcoin node unavailable while verifying the payout: {0}")]
    NodeUnavailable(String),
    #[error("withdrawal index {0} is out of range")]
    IndexOutOfRange(u64),
    #[error("stored payout data for withdrawal {index} is unusable: {reason}")]
    MalformedLocalState { index: u64, reason: String },
}

/// The facts a validator agrees to attest, once it has verified them itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionAttestation {
    pub withdrawal_index: u64,
    pub payout_txid: [u8; 32],
    pub payout_height: u64,
    pub amount: u64,
    /// `sha256` of the Goldcoin address **exactly as the on-chain account
    /// stores it** — see [`crate::solana::instruction::destination_commitment`].
    pub dest_commitment: [u8; 32],
}

/// A validator's completion view, over its own database and its own node.
pub struct CompletionView<R: PayoutRpc> {
    rpc: R,
    /// The confirmation depth a payout must reach. Reused from the
    /// withdrawal config rather than configured separately (owner decision
    /// Q2): two knobs could disagree, and the dangerous direction is silent.
    confirmation_depth: i64,
}

impl<R: PayoutRpc> CompletionView<R> {
    pub fn new(rpc: R, confirmation_depth: i64) -> Self {
        CompletionView {
            rpc,
            confirmation_depth,
        }
    }

    /// Decides whether to attest, checking cheap local state before ever
    /// touching the node.
    pub async fn attest(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
    ) -> Result<CompletionAttestation, CompletionRefusal> {
        let index = i64::try_from(withdrawal_index)
            .map_err(|_| CompletionRefusal::IndexOutOfRange(withdrawal_index))?;

        let w = db
            .get_withdrawal(index)
            .map_err(|e| CompletionRefusal::MalformedLocalState {
                index: withdrawal_index,
                reason: e.to_string(),
            })?
            .ok_or(CompletionRefusal::UnknownWithdrawal(withdrawal_index))?;

        // This validator must have completed the payout ITSELF. Attesting
        // from any earlier state would mean vouching for a payment it has
        // not seen through.
        if w.state != WithdrawalState::Completed {
            return Err(CompletionRefusal::NotLocallyCompleted {
                index: withdrawal_index,
                state: w.state.as_str().to_string(),
            });
        }

        let payout = db
            .get_payout(index)
            .map_err(|e| CompletionRefusal::MalformedLocalState {
                index: withdrawal_index,
                reason: e.to_string(),
            })?
            .ok_or(CompletionRefusal::NoPayout(withdrawal_index))?;

        let local_txid_hex =
            payout
                .txid_hex
                .clone()
                .ok_or(CompletionRefusal::MalformedLocalState {
                    index: withdrawal_index,
                    reason: "completed payout has no txid".to_string(),
                })?;
        let requested_hex = crate::glc::hex::encode(&{
            let mut t = payout_txid;
            t.reverse();
            t
        });
        if requested_hex != local_txid_hex {
            return Err(CompletionRefusal::TxidMismatch {
                requested: requested_hex,
                local: local_txid_hex,
            });
        }

        // Only now is the node consulted — an attacker cannot make this
        // validator do RPC work by naming a withdrawal it has not paid.
        let status = self
            .rpc
            .transaction_confirmations(&local_txid_hex)
            .await
            .map_err(|e| CompletionRefusal::NodeUnavailable(e.to_string()))?;
        let TxStatus {
            confirmations,
            block_height,
            ..
        } = match status {
            Some(s) => s,
            None => return Err(CompletionRefusal::PayoutUnknownToNode(local_txid_hex)),
        };

        // Q2: one confirmation policy for payout and completion.
        if confirmations < self.confirmation_depth {
            return Err(CompletionRefusal::InsufficientConfirmations {
                index: withdrawal_index,
                confirmations,
                required: self.confirmation_depth,
            });
        }

        // The height is part of what gets recorded on-chain forever, so it
        // is checked against this node's own observation rather than taken
        // on trust.
        let local_height = block_height.unwrap_or(0) as u64;
        if local_height != payout_height {
            return Err(CompletionRefusal::HeightMismatch {
                requested: payout_height,
                local: local_height,
            });
        }

        Ok(CompletionAttestation {
            withdrawal_index,
            payout_txid,
            payout_height,
            amount: w.amount_atomic,
            dest_commitment: crate::solana::instruction::destination_commitment(
                w.glc_address.as_bytes(),
            ),
        })
    }
}
