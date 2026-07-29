//! Admin-gated governance instructions: pause, validator-set rotation, and
//! the two-step admin handover.
//!
//! Every context checks `bridge_config.admin == admin.key()` (or, for
//! `accept_admin`, the stored `pending_admin`) with a custom error, and
//! addresses the PDAs by their stored bumps. Admin instructions remain
//! callable while paused — the pause flag gates the value-moving paths
//! (Phase 2+), never governance, otherwise un-pausing would be impossible.

use anchor_lang::prelude::*;

use crate::constants::{SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET};
use crate::errors::BridgeError;
use crate::events::{
    AdminTransferInitiated, AdminTransferred, PauseStateChanged, ValidatorSetUpdated,
};
use crate::state::{BridgeConfig, ValidatorSet};
use crate::validation::validate_validator_set;

#[derive(Accounts)]
pub struct AdminConfig<'info> {
    pub admin: Signer<'info>,
    #[account(
        mut,
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin
    )]
    pub bridge_config: Account<'info, BridgeConfig>,
}

#[derive(Accounts)]
pub struct UpdateValidatorSet<'info> {
    pub admin: Signer<'info>,
    #[account(
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin
    )]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(
        mut,
        seeds = [SEED_VALIDATOR_SET],
        bump = validator_set.bump
    )]
    pub validator_set: Account<'info, ValidatorSet>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    /// The pending admin accepting the handover.
    pub new_admin: Signer<'info>,
    #[account(
        mut,
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump
    )]
    pub bridge_config: Account<'info, BridgeConfig>,
}

/// Flips the circuit breaker. A no-op flip is rejected so a stale client
/// can't silently "succeed" while observing the opposite state.
pub fn set_paused(ctx: Context<AdminConfig>, paused: bool) -> Result<()> {
    let config = &mut ctx.accounts.bridge_config;
    require!(config.paused != paused, BridgeError::PauseStateUnchanged);
    config.paused = paused;
    emit!(PauseStateChanged { paused });
    Ok(())
}

/// Replaces the federation set/threshold under the same invariants as
/// `initialize` and advances the epoch, invalidating any Phase 3 proofs
/// signed under the previous set.
pub fn update_validator_set(
    ctx: Context<UpdateValidatorSet>,
    validators: Vec<Pubkey>,
    threshold: u8,
) -> Result<()> {
    validate_validator_set(&validators, threshold)?;

    let set = &mut ctx.accounts.validator_set;
    set.epoch = set
        .epoch
        .checked_add(1)
        .ok_or(BridgeError::ArithmeticOverflow)?;
    set.threshold = threshold;
    let validator_count = validators.len() as u8;
    set.validators = validators;

    emit!(ValidatorSetUpdated {
        epoch: set.epoch,
        threshold,
        validator_count,
    });
    Ok(())
}

/// Step 1 of the admin handover: propose a new admin. Overwriting an earlier
/// un-accepted proposal is allowed (that is also how a pending transfer is
/// effectively cancelled: propose a different key, or hand over normally).
pub fn transfer_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.bridge_config;
    require!(new_admin != config.admin, BridgeError::AdminUnchanged);
    config.pending_admin = Some(new_admin);
    emit!(AdminTransferInitiated {
        admin: config.admin,
        pending_admin: new_admin,
    });
    Ok(())
}

/// Step 2 of the admin handover: only the proposed key may accept, proving
/// the new admin actually controls it before governance switches.
pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
    let config = &mut ctx.accounts.bridge_config;
    let pending = config.pending_admin.ok_or(BridgeError::NoPendingAdmin)?;
    require!(
        pending == ctx.accounts.new_admin.key(),
        BridgeError::PendingAdminMismatch
    );
    let previous_admin = config.admin;
    config.admin = pending;
    config.pending_admin = None;
    emit!(AdminTransferred {
        previous_admin,
        new_admin: config.admin,
    });
    Ok(())
}
