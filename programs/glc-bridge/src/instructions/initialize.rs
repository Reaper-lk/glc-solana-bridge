//! One-time bridge initialization.
//!
//! Authorization (ADR-0008): only the program's upgrade authority may
//! initialize, proven by matching the signer against the loader-v3
//! `ProgramData` account. This closes the initialization-front-running
//! window on a fresh deployment — first-caller-wins is explicitly rejected.
//! The initializer becomes the initial admin; governance can then be handed
//! over via the two-step admin transfer.
//!
//! Reinitialization is structurally impossible: both accounts are created
//! with Anchor `init` on fixed seeds, and account creation fails if the
//! account already exists.
//!
//! The wrapped SPL mint is NOT created here — that is Phase 2 work, gated on
//! the freeze-authority custody decision (ADR-0008, docs/custody.md #6).

use anchor_lang::prelude::*;

use crate::constants::{PROTOCOL_VERSION, SEED_BRIDGE_CONFIG, SEED_VALIDATOR_SET};
use crate::errors::BridgeError;
use crate::events::BridgeInitialized;
use crate::state::{BridgeConfig, ValidatorSet};
use crate::validation::validate_validator_set;

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The program upgrade authority; pays rent and becomes the initial
    /// admin.
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = BridgeConfig::SPACE,
        seeds = [SEED_BRIDGE_CONFIG],
        bump
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        init,
        payer = authority,
        space = ValidatorSet::SPACE,
        seeds = [SEED_VALIDATOR_SET],
        bump
    )]
    pub validator_set: Account<'info, ValidatorSet>,

    /// This program's own executable account; ties `program_data` to the
    /// genuine loader-v3 ProgramData address (an attacker cannot substitute
    /// a ProgramData account they control).
    #[account(
        constraint = program.programdata_address()? == Some(program_data.key())
            @ BridgeError::UnauthorizedInitializer
    )]
    pub program: Program<'info, crate::program::GlcBridge>,

    #[account(
        constraint = program_data.upgrade_authority_address == Some(authority.key())
            @ BridgeError::UnauthorizedInitializer
    )]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

pub fn initialize(
    ctx: Context<Initialize>,
    validators: Vec<Pubkey>,
    threshold: u8,
    min_deposit: u64,
    min_withdrawal: u64,
) -> Result<()> {
    validate_validator_set(&validators, threshold)?;

    let config = &mut ctx.accounts.bridge_config;
    config.protocol_version = PROTOCOL_VERSION;
    config.admin = ctx.accounts.authority.key();
    config.pending_admin = None;
    config.paused = false;
    config.withdrawal_count = 0;
    config.min_deposit = min_deposit;
    config.min_withdrawal = min_withdrawal;
    config.bump = ctx.bumps.bridge_config;
    config.reserved = [0u8; 64];

    let validator_count = validators.len() as u8;
    let set = &mut ctx.accounts.validator_set;
    set.epoch = 0;
    set.threshold = threshold;
    set.bump = ctx.bumps.validator_set;
    set.validators = validators;
    set.reserved = [0u8; 32];

    emit!(BridgeInitialized {
        admin: config.admin,
        protocol_version: PROTOCOL_VERSION,
        threshold,
        validator_count,
    });
    Ok(())
}
