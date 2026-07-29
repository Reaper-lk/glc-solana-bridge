//! # TEMPORARY Phase 2 test scaffolding — NOT federation verification
//!
//! `mint_wrapped_testonly` authorizes minting with a plain **admin
//! signature**. It exists so the entire deposit-claim path — claim-PDA
//! replay guard, pause, minimum-deposit, epoch binding, ATA checks, and the
//! `MintToChecked` CPI — is real and tested before Phase 3 adds the
//! federation's M-of-N proof verification (ADR-0005, ADR-0009).
//!
//! In Phase 3 this instruction is **deleted, not renamed**: the production
//! `mint_wrapped` replaces it with aggregated-proof verification in place of
//! the admin signature. Nothing in this module may ever be mistaken for
//! production-ready federation verification, and deployment beyond
//! localnet/test remains blocked by policy while it exists
//! (docs/threat-model.md).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token::{spl_token, Mint, Token, TokenAccount};

use crate::constants::{
    SEED_BRIDGE_CONFIG, SEED_DEPOSIT_CLAIM, SEED_MINT_AUTHORITY, SEED_VALIDATOR_SET,
    WRAPPED_GLC_DECIMALS,
};
use crate::errors::BridgeError;
use crate::events::DepositClaimMinted;
use crate::state::{BridgeConfig, DepositClaim, ValidatorSet};

#[derive(Accounts)]
#[instruction(txid: [u8; 32], vout: u32)]
pub struct MintWrappedTestonly<'info> {
    /// TEMPORARY authorization: the bridge admin. Replaced by federation
    /// M-of-N proof verification in Phase 3 (see module docs).
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin,
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
        payer = admin,
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
    /// used: it anchors the associated-token-account derivation below and is
    /// recorded in the claim.
    pub recipient: UncheckedAccount<'info>,

    /// Must be the recipient's Associated Token Account for the wrapped
    /// mint (owner decision: ATA required, arbitrary token accounts
    /// rejected).
    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = recipient,
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn mint_wrapped_testonly(
    ctx: Context<MintWrappedTestonly>,
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

    // MintToChecked: the token program re-verifies `decimals` against the
    // mint, closing any decimals-confusion path.
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
