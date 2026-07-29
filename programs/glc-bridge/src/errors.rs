//! Program error taxonomy. Only errors that a currently implemented
//! instruction can raise are defined; the deposit/withdrawal taxonomy
//! (bad proof, claim already processed, bridge paused, …) lands with those
//! instructions in Phases 2–3.

use anchor_lang::prelude::*;

#[error_code]
pub enum BridgeError {
    #[msg("Validator set must contain at least one validator")]
    EmptyValidatorSet,
    #[msg("Validator set exceeds MAX_VALIDATORS")]
    TooManyValidators,
    #[msg("Validator set contains a duplicate key")]
    DuplicateValidator,
    #[msg("Validator key is the all-zero (default) pubkey, which cannot sign")]
    InvalidValidatorKey,
    #[msg("Signature threshold must be at least one")]
    ZeroThreshold,
    #[msg("Signature threshold exceeds the number of validators")]
    ThresholdExceedsValidatorCount,
    #[msg("Signer is not the program upgrade authority")]
    UnauthorizedInitializer,
    #[msg("Signer is not the bridge admin")]
    UnauthorizedAdmin,
    #[msg("Pause state is already set to the requested value")]
    PauseStateUnchanged,
    #[msg("New admin is the same as the current admin")]
    AdminUnchanged,
    #[msg("No admin transfer is pending")]
    NoPendingAdmin,
    #[msg("Signer is not the pending admin")]
    PendingAdminMismatch,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
