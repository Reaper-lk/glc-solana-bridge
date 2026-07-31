//! Anchor events.
//!
//! Design rule (docs/adr/0006): events are a UX/indexing convenience ONLY.
//! Anything the bridge must not lose — above all withdrawal requests — is
//! stored in persistent accounts, because Solana log delivery is best-effort
//! and logs are truncated/pruned. Every fact below is recoverable from
//! `BridgeConfig` / `ValidatorSet` account state.
//!

use anchor_lang::prelude::*;

/// Bridge state created (`initialize`).
#[event]
pub struct BridgeInitialized {
    pub admin: Pubkey,
    pub protocol_version: u8,
    pub threshold: u8,
    pub validator_count: u8,
}

/// Validator set and/or threshold replaced; `epoch` is the new epoch.
#[event]
pub struct ValidatorSetUpdated {
    pub epoch: u64,
    pub threshold: u8,
    pub validator_count: u8,
}

/// Circuit breaker toggled.
#[event]
pub struct PauseStateChanged {
    pub paused: bool,
}

/// Step 1 of the two-step admin handover: a transfer was proposed.
#[event]
pub struct AdminTransferInitiated {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
}

/// Step 2 of the two-step admin handover: the pending admin accepted.
#[event]
pub struct AdminTransferred {
    pub previous_admin: Pubkey,
    pub new_admin: Pubkey,
}

/// The wrapped-GLC SPL mint was created (`create_wrapped_mint`, once ever).
#[event]
pub struct WrappedMintCreated {
    pub mint: Pubkey,
    pub mint_authority: Pubkey,
    pub decimals: u8,
}

/// A deposit claim was processed and wrapped GLC minted 1:1. Advisory only —
/// the `DepositClaim` account is the authoritative record (ADR-0006).
#[event]
pub struct DepositClaimMinted {
    pub txid: [u8; 32],
    pub vout: u32,
    pub recipient: Pubkey,
    pub amount: u64,
    pub epoch: u64,
}

/// Wrapped GLC burned and a payout obligation recorded. Advisory only — the
/// `WithdrawalRequest` account is the authoritative record relayers scan
/// (ADR-0006).
#[event]
pub struct WithdrawalRequested {
    pub index: u64,
    pub requester: Pubkey,
    pub amount: u64,
    pub glc_address: Vec<u8>,
}

/// A validator rotation was threshold-approved and queued behind the
/// timelock (Phase 7a, ADR-0014). Emitted so observers can react during the
/// delay window — the whole purpose of the timelock.
#[event]
pub struct GovernanceActionProposed {
    pub action: u8,
    pub proposed_under_epoch: u64,
    pub eta: i64,
    pub threshold: u8,
    pub validator_count: u8,
}

/// A queued governance action was executed after its timelock elapsed.
#[event]
pub struct GovernanceActionExecuted {
    pub action: u8,
    pub new_epoch: u64,
}

/// A queued governance action was cancelled before execution.
#[event]
pub struct GovernanceActionCancelled {
    pub action: u8,
    pub eta: i64,
}
