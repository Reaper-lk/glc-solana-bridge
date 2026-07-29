//! Anchor events.
//!
//! Design rule (docs/adr/0006): events are a UX/indexing convenience ONLY.
//! Anything the bridge must not lose — above all withdrawal requests — is
//! stored in persistent accounts, because Solana log delivery is best-effort
//! and logs are truncated/pruned. Every fact below is recoverable from
//! `BridgeConfig` / `ValidatorSet` account state.
//!
//! Planned (Phase 2–3):
//! - `DepositMinted { deposit_txid, vout, amount, recipient }`
//! - `WithdrawalRequested { withdrawal_index, amount, glc_address }`

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
