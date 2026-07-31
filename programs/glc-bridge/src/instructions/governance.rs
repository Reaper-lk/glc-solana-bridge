//! Threshold-gated, timelocked governance (Phase 7a, ADR-0014).
//!
//! # What this replaces, and why
//!
//! Until Phase 7a, `update_validator_set` was gated by a single admin key.
//! Because the validator set *is* the mint authority, that key was an
//! indirect **infinite-mint capability**: whoever held it could rotate the
//! federation to keys they controlled and mint without limit. ADR-0007
//! anticipated this being fixed in Phase 3; it was not, and
//! docs/threat-model.md has carried it as an open risk ever since.
//!
//! Rotation now requires the same M-of-N federation proof as a deposit mint
//! (ADR-0010) **and** must sit visibly in a timelock before it takes effect.
//! No new authorization mechanism is introduced — the ed25519-precompile
//! parser in [`crate::verification`] is reused verbatim, so governance
//! inherits every property that path was already audited and tested for.
//!
//! # Flow
//!
//! ```text
//!   propose_validator_rotation   (M-of-N proof over the CURRENT epoch)
//!            │  creates the singleton PendingGovernanceAction { eta }
//!            ▼
//!     ... timelock window: publicly observable, cancellable ...
//!            │
//!   execute_validator_rotation   (permissionless once eta has passed)
//!            │  applies the set, increments the epoch, closes the account
//!            ▼
//!   cancel_validator_rotation    (M-of-N proof, any time before execution)
//! ```
//!
//! Execution is deliberately **permissionless**: the authorization was the
//! threshold proof at proposal time, and the delay is what gives observers
//! their window. Requiring a second proof to execute would let a minority
//! that had gone offline silently veto an approved action.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;
use anchor_lang::solana_program::sysvar::instructions::{
    get_instruction_relative, ID as INSTRUCTIONS_SYSVAR_ID,
};
use glc_bridge_shared::governance::{
    cancel_params, governance_message, rotation_params, ACTION_CANCEL_ROTATION,
    ACTION_PROPOSE_ROTATION,
};

use crate::constants::{SEED_BRIDGE_CONFIG, SEED_GOVERNANCE_ACTION, SEED_VALIDATOR_SET};
use crate::errors::BridgeError;
use crate::events::{
    GovernanceActionCancelled, GovernanceActionExecuted, GovernanceActionProposed,
};
use crate::state::{BridgeConfig, PendingGovernanceAction, ValidatorSet};
use crate::validation::validate_validator_set;
use crate::verification::count_unique_validator_signers;

/// Verifies that the instruction immediately before this one is an ed25519
/// precompile instruction carrying at least `threshold` unique current
/// validators' signatures over `expected_message`.
///
/// Byte-for-byte the same check `mint_wrapped` performs — extracted here so
/// both paths provably share one implementation rather than two that could
/// drift apart.
fn require_federation_approval(
    instructions_sysvar: &AccountInfo,
    validator_set: &ValidatorSet,
    expected_message: &[u8],
) -> Result<()> {
    let verification_ix = get_instruction_relative(-1, instructions_sysvar)
        .map_err(|_| BridgeError::MissingSignatureVerification)?;
    require!(
        verification_ix.program_id == anchor_lang::solana_program::ed25519_program::ID,
        BridgeError::MissingSignatureVerification
    );
    let signer_count = count_unique_validator_signers(
        &verification_ix.data,
        expected_message,
        &validator_set.validators,
    )?;
    require!(
        signer_count >= usize::from(validator_set.threshold),
        BridgeError::InsufficientSignatures
    );
    Ok(())
}

// ---------------------------------------------------------------- propose --

#[derive(Accounts)]
pub struct ProposeGovernanceAction<'info> {
    /// Any fee payer; funds the pending-action account's rent. Confers no
    /// authority — the federation proof is the only authorization, exactly
    /// as with `mint_wrapped` (owner decision U7).
    #[account(mut)]
    pub proposer: Signer<'info>,

    #[account(seeds = [SEED_BRIDGE_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(seeds = [SEED_VALIDATOR_SET], bump = validator_set.bump)]
    pub validator_set: Account<'info, ValidatorSet>,

    /// Singleton: `init` fails if an action is already pending, so a
    /// backlog can never be queued.
    #[account(
        init,
        payer = proposer,
        space = PendingGovernanceAction::SPACE,
        seeds = [SEED_GOVERNANCE_ACTION],
        bump
    )]
    pub pending_action: Account<'info, PendingGovernanceAction>,

    /// CHECK: the Instructions sysvar, address-pinned; read to locate the
    /// ed25519 verification instruction in this transaction.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Queues a validator-set rotation behind the timelock.
///
/// The proposed parameters are validated here, at proposal time, under the
/// same invariants `initialize` enforces — an invalid set must never sit in
/// the queue looking legitimate, and must never be discovered to be
/// unexecutable only after the delay has elapsed.
pub fn propose_validator_rotation(
    ctx: Context<ProposeGovernanceAction>,
    validators: Vec<Pubkey>,
    threshold: u8,
) -> Result<()> {
    validate_validator_set(&validators, threshold)?;

    let config = &ctx.accounts.bridge_config;
    let validator_set = &ctx.accounts.validator_set;

    // The signed message commits to a hash of the parameters rather than the
    // parameters themselves: inlining up to 16 pubkeys would push a
    // 4-signature rotation past the legacy transaction limit on its own
    // (see the shared crate's module docs). The binding is equally strong —
    // the hash is recomputed here from the instruction's own arguments.
    let raw: Vec<[u8; 32]> = validators.iter().map(|v| v.to_bytes()).collect();
    let params_commitment = hash(&rotation_params(threshold, &raw)).to_bytes();
    let expected_message = governance_message(
        config.protocol_version,
        &crate::ID.to_bytes(),
        validator_set.epoch,
        ACTION_PROPOSE_ROTATION,
        &params_commitment,
    );
    require_federation_approval(
        &ctx.accounts.instructions_sysvar.to_account_info(),
        validator_set,
        &expected_message,
    )?;

    let eta = Clock::get()?
        .unix_timestamp
        .checked_add(config.governance_timelock_seconds)
        .ok_or(BridgeError::ArithmeticOverflow)?;

    let validator_count = validators.len() as u8;
    let pending = &mut ctx.accounts.pending_action;
    pending.action = ACTION_PROPOSE_ROTATION;
    pending.proposed_under_epoch = validator_set.epoch;
    pending.eta = eta;
    pending.threshold = threshold;
    pending.validators = validators;
    pending.bump = ctx.bumps.pending_action;
    pending.reserved = [0u8; 32];

    emit!(GovernanceActionProposed {
        action: ACTION_PROPOSE_ROTATION,
        proposed_under_epoch: pending.proposed_under_epoch,
        eta,
        threshold,
        validator_count,
    });
    Ok(())
}

// ---------------------------------------------------------------- execute --

#[derive(Accounts)]
pub struct ExecuteGovernanceAction<'info> {
    /// Permissionless: rent is refunded here. Confers no authority.
    #[account(mut)]
    pub executor: Signer<'info>,

    #[account(seeds = [SEED_BRIDGE_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(mut, seeds = [SEED_VALIDATOR_SET], bump = validator_set.bump)]
    pub validator_set: Account<'info, ValidatorSet>,

    /// Closed on success, refunding rent and freeing the singleton slot.
    #[account(
        mut,
        close = executor,
        seeds = [SEED_GOVERNANCE_ACTION],
        bump = pending_action.bump
    )]
    pub pending_action: Account<'info, PendingGovernanceAction>,
}

/// Applies a queued rotation once its timelock has elapsed.
pub fn execute_validator_rotation(ctx: Context<ExecuteGovernanceAction>) -> Result<()> {
    let pending = &ctx.accounts.pending_action;
    require!(
        pending.action == ACTION_PROPOSE_ROTATION,
        BridgeError::WrongGovernanceAction
    );
    require!(
        Clock::get()?.unix_timestamp >= pending.eta,
        BridgeError::GovernanceTimelockNotElapsed
    );

    let set = &mut ctx.accounts.validator_set;
    // A proposal approved by one federation must never be applied by a
    // different one. Nothing in the current instruction surface can bump the
    // epoch while an action is pending, so this is defence in depth rather
    // than a reachable path today — but it costs one comparison and removes
    // an entire class of future mistake.
    require!(
        set.epoch == pending.proposed_under_epoch,
        BridgeError::StaleGovernanceProposal
    );

    // Re-validate at execution: the invariants were checked at proposal
    // time, but the account has been writable in between and this is the
    // last point before the federation actually changes.
    validate_validator_set(&pending.validators, pending.threshold)?;

    set.epoch = set
        .epoch
        .checked_add(1)
        .ok_or(BridgeError::ArithmeticOverflow)?;
    set.threshold = pending.threshold;
    set.validators = pending.validators.clone();

    emit!(GovernanceActionExecuted {
        action: ACTION_PROPOSE_ROTATION,
        new_epoch: set.epoch,
    });
    Ok(())
}

// ----------------------------------------------------------------- cancel --

#[derive(Accounts)]
pub struct CancelGovernanceAction<'info> {
    /// Rent refund recipient. Confers no authority — cancellation is
    /// authorized by the federation proof alone.
    #[account(mut)]
    pub canceller: Signer<'info>,

    #[account(seeds = [SEED_BRIDGE_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(seeds = [SEED_VALIDATOR_SET], bump = validator_set.bump)]
    pub validator_set: Account<'info, ValidatorSet>,

    #[account(
        mut,
        close = canceller,
        seeds = [SEED_GOVERNANCE_ACTION],
        bump = pending_action.bump
    )]
    pub pending_action: Account<'info, PendingGovernanceAction>,

    /// CHECK: the Instructions sysvar, address-pinned.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

/// Cancels the pending action, freeing the singleton slot.
///
/// Requires a fresh M-of-N proof: cancellation is how a hostile or mistaken
/// proposal is stopped during its window, so it must be at least as hard to
/// obtain as the proposal itself. The signed message commits to the specific
/// action being cancelled (its type and `eta`), so a cancel signature cannot
/// be replayed against a later re-proposal.
pub fn cancel_validator_rotation(ctx: Context<CancelGovernanceAction>) -> Result<()> {
    let config = &ctx.accounts.bridge_config;
    let validator_set = &ctx.accounts.validator_set;
    let pending = &ctx.accounts.pending_action;

    let params_commitment = hash(&cancel_params(pending.action, pending.eta)).to_bytes();
    let expected_message = governance_message(
        config.protocol_version,
        &crate::ID.to_bytes(),
        validator_set.epoch,
        ACTION_CANCEL_ROTATION,
        &params_commitment,
    );
    require_federation_approval(
        &ctx.accounts.instructions_sysvar.to_account_info(),
        validator_set,
        &expected_message,
    )?;

    emit!(GovernanceActionCancelled {
        action: pending.action,
        eta: pending.eta,
    });
    Ok(())
}
