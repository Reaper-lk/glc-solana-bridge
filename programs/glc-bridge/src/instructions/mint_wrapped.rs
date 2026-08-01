//! Production deposit-claim mint path (ADR-0010). Replaces the Phase 2
//! `mint_wrapped_testonly` scaffolding, which was deleted per ADR-0009.
//!
//! Authorization is an M-of-N federation proof: the transaction carries one
//! ed25519-precompile instruction, immediately before this one, in which at
//! least `threshold` distinct current validators signed the canonical claim
//! message ([`glc_bridge_shared::claim`]). The runtime verified the
//! signatures before execution; [`crate::verification`] proves what was
//! signed and by whom. The submitter can be anyone — a valid proof is the
//! only authority, and the submitter merely pays fees and claim rent
//! (owner decision U7).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::sysvar::instructions::{
    get_instruction_relative, ID as INSTRUCTIONS_SYSVAR_ID,
};
use anchor_spl::token::{spl_token, Mint, Token, TokenAccount};
use glc_bridge_shared::claim::deposit_claim_message;

use crate::constants::{
    SEED_BRIDGE_CONFIG, SEED_DEPOSIT_CLAIM, SEED_MINT_AUTHORITY, SEED_VALIDATOR_SET,
    WRAPPED_GLC_DECIMALS,
};
use crate::errors::BridgeError;
use crate::events::DepositClaimMinted;
use crate::state::{BridgeConfig, DepositClaim, ValidatorSet};
use crate::verification::count_unique_validator_signers;

#[derive(Accounts)]
#[instruction(txid: [u8; 32], vout: u32)]
pub struct MintWrapped<'info> {
    /// Any fee payer; funds the claim account's rent. Confers no authority.
    #[account(mut)]
    pub submitter: Signer<'info>,

    #[account(
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.wrapped_mint != Pubkey::default()
            @ BridgeError::MintNotConfigured
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(seeds = [SEED_VALIDATOR_SET], bump = validator_set.bump)]
    pub validator_set: Account<'info, ValidatorSet>,

    /// Existence of this account is the replay guard (ADR-0003): a second
    /// mint for the same `(txid, vout)` fails right here at `init`.
    #[account(
        init,
        payer = submitter,
        space = DepositClaim::SPACE,
        seeds = [SEED_DEPOSIT_CLAIM, txid.as_ref(), &vout.to_le_bytes()],
        bump
    )]
    pub deposit_claim: Account<'info, DepositClaim>,

    #[account(
        mut,
        address = bridge_config.wrapped_mint @ BridgeError::WrongWrappedMint
    )]
    pub wrapped_mint: Account<'info, Mint>,

    /// CHECK: data-less PDA; sole mint authority (ADR-0004). Address is
    /// fully constrained by seeds + the stored canonical bump.
    #[account(seeds = [SEED_MINT_AUTHORITY], bump = bridge_config.mint_authority_bump)]
    pub mint_authority: UncheckedAccount<'info>,

    /// CHECK: the deposit's bound Solana recipient. Only its address is
    /// used: it anchors the ATA derivation below, is committed to inside the
    /// signed claim message, and is recorded in the claim.
    pub recipient: UncheckedAccount<'info>,

    /// Must be the recipient's Associated Token Account for the wrapped
    /// mint (owner decision: ATA required).
    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = recipient,
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,

    /// CHECK: the Instructions sysvar, address-pinned; read to locate the
    /// ed25519 verification instruction in this transaction.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn mint_wrapped(
    ctx: Context<MintWrapped>,
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    epoch: u64,
) -> Result<()> {
    let config = &ctx.accounts.bridge_config;
    let validator_set = &ctx.accounts.validator_set;

    require!(!config.paused, BridgeError::BridgePaused);
    require!(
        epoch == validator_set.epoch,
        BridgeError::StaleValidatorEpoch
    );
    require!(amount > 0, BridgeError::ZeroDepositAmount);
    require!(
        amount >= config.min_deposit,
        BridgeError::BelowMinimumDeposit
    );

    // The wrapped-supply ceiling (Phase 7h-0, ADR-0014 §11). Checked BEFORE
    // minting and before the federation proof is verified, so a mint that
    // would breach the cap costs nothing to reject.
    //
    // Bounding total exposure on-chain is not the same as monitoring it: a
    // monitor tells an operator afterwards, this refuses. Threat-model
    // invariant #1 is the only standing invariant with no runtime
    // enforcement, and this is the half that can be enforced by the program.
    //
    // `checked_add` rather than a comparison on the sum: an overflow would
    // wrap to a small number and pass a naive check, which is exactly the
    // input an attacker would look for.
    let projected_supply = ctx
        .accounts
        .wrapped_mint
        .supply
        .checked_add(amount)
        .ok_or(BridgeError::ArithmeticOverflow)?;
    require!(
        projected_supply <= config.max_wrapped_supply,
        BridgeError::WrappedSupplyCapExceeded
    );

    // The federation proof: the instruction directly before this one must
    // be the ed25519 precompile carrying >= threshold unique current
    // validators over exactly the canonical claim bytes.
    let verification_ix =
        get_instruction_relative(-1, &ctx.accounts.instructions_sysvar.to_account_info())
            .map_err(|_| BridgeError::MissingSignatureVerification)?;
    require!(
        verification_ix.program_id == anchor_lang::solana_program::ed25519_program::ID,
        BridgeError::MissingSignatureVerification
    );
    let expected_message = deposit_claim_message(
        config.protocol_version,
        &crate::ID.to_bytes(),
        validator_set.epoch,
        &txid,
        vout,
        amount,
        &ctx.accounts.recipient.key().to_bytes(),
        &config.wrapped_mint.to_bytes(),
    );
    let signer_count = count_unique_validator_signers(
        &verification_ix.data,
        &expected_message,
        &validator_set.validators,
    )?;
    require!(
        signer_count >= usize::from(validator_set.threshold),
        BridgeError::InsufficientSignatures
    );

    let ix = spl_token::instruction::mint_to_checked(
        ctx.accounts.token_program.key,
        &ctx.accounts.wrapped_mint.key(),
        &ctx.accounts.recipient_token_account.key(),
        ctx.accounts.mint_authority.key,
        &[],
        amount,
        WRAPPED_GLC_DECIMALS,
    )?;
    invoke_signed(
        &ix,
        &[
            ctx.accounts.wrapped_mint.to_account_info(),
            ctx.accounts.recipient_token_account.to_account_info(),
            ctx.accounts.mint_authority.to_account_info(),
        ],
        &[&[SEED_MINT_AUTHORITY, &[config.mint_authority_bump]]],
    )?;

    let claim = &mut ctx.accounts.deposit_claim;
    claim.txid = txid;
    claim.vout = vout;
    claim.amount = amount;
    claim.recipient = ctx.accounts.recipient.key();
    claim.epoch = validator_set.epoch;
    claim.protocol_version = config.protocol_version;
    claim.slot_created = Clock::get()?.slot;
    claim.bump = ctx.bumps.deposit_claim;
    claim.reserved = [0u8; 16];

    emit!(DepositClaimMinted {
        txid,
        vout,
        recipient: claim.recipient,
        amount,
        epoch: claim.epoch,
    });
    Ok(())
}
