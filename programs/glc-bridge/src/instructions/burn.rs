//! Withdrawal request path: burn wrapped GLC and record the payout
//! obligation, atomically (ADR-0006). There is no state in which value was
//! burned without a persistent, queryable `WithdrawalRequest` account.
//!
//! The GLC destination is opaque ASCII (length-bounded only) until the real
//! address format is verified against a node in Phase 4 (owner decision U3).
//! Status write-back (`Broadcast`/`Completed`) is deliberately not
//! implemented in Phase 3 (owner decision U2).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token::{spl_token, Mint, Token, TokenAccount};

use crate::constants::{
    MAX_GLC_ADDRESS_LEN, SEED_BRIDGE_CONFIG, SEED_WITHDRAWAL, WRAPPED_GLC_DECIMALS,
};
use crate::errors::BridgeError;
use crate::events::WithdrawalRequested;
use crate::state::{BridgeConfig, WithdrawalRequest, WithdrawalStatus};

#[derive(Accounts)]
pub struct BurnWrapped<'info> {
    /// The wallet burning its wrapped GLC; signs the burn and pays the
    /// record's rent.
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.wrapped_mint != Pubkey::default()
            @ BridgeError::MintNotConfigured
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    #[account(
        mut,
        address = bridge_config.wrapped_mint @ BridgeError::WrongWrappedMint
    )]
    pub wrapped_mint: Account<'info, Mint>,

    /// Must be the user's Associated Token Account for the wrapped mint
    /// (owner decision U4).
    #[account(
        mut,
        associated_token::mint = wrapped_mint,
        associated_token::authority = user,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    /// The persistent payout obligation, seeded by the CURRENT counter
    /// value; the counter increments in the handler.
    #[account(
        init,
        payer = user,
        space = WithdrawalRequest::SPACE,
        seeds = [SEED_WITHDRAWAL, &bridge_config.withdrawal_count.to_le_bytes()],
        bump
    )]
    pub withdrawal_request: Account<'info, WithdrawalRequest>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn burn_wrapped(ctx: Context<BurnWrapped>, amount: u64, glc_address: Vec<u8>) -> Result<()> {
    let config = &ctx.accounts.bridge_config;

    require!(!config.paused, BridgeError::BridgePaused);
    require!(amount > 0, BridgeError::ZeroWithdrawalAmount);
    require!(
        amount >= config.min_withdrawal,
        BridgeError::BelowMinimumWithdrawal
    );
    require!(
        !glc_address.is_empty() && glc_address.len() <= MAX_GLC_ADDRESS_LEN,
        BridgeError::InvalidGlcAddressLength
    );

    // Fail on counter exhaustion before any value moves (the transaction
    // would revert anyway; this keeps the error explicit).
    let index = config.withdrawal_count;
    let next_count = index
        .checked_add(1)
        .ok_or(BridgeError::ArithmeticOverflow)?;

    // BurnChecked: the token program re-verifies decimals against the mint.
    // The user signs their own burn — no PDA authority involved.
    let ix = spl_token::instruction::burn_checked(
        ctx.accounts.token_program.key,
        &ctx.accounts.user_token_account.key(),
        &ctx.accounts.wrapped_mint.key(),
        ctx.accounts.user.key,
        &[],
        amount,
        WRAPPED_GLC_DECIMALS,
    )?;
    invoke(
        &ix,
        &[
            ctx.accounts.user_token_account.to_account_info(),
            ctx.accounts.wrapped_mint.to_account_info(),
            ctx.accounts.user.to_account_info(),
        ],
    )?;

    let record = &mut ctx.accounts.withdrawal_request;
    record.index = index;
    record.amount = amount;
    record.requester = ctx.accounts.user.key();
    record.glc_address = [0u8; 64];
    record.glc_address[..glc_address.len()].copy_from_slice(&glc_address);
    record.glc_address_len = glc_address.len() as u8;
    record.status = WithdrawalStatus::Pending;
    record.requested_at_slot = Clock::get()?.slot;
    record.protocol_version = config.protocol_version;
    record.bump = ctx.bumps.withdrawal_request;
    record.reserved = [0u8; 48];

    ctx.accounts.bridge_config.withdrawal_count = next_count;

    emit!(WithdrawalRequested {
        index,
        requester: record.requester,
        amount,
        glc_address,
    });
    Ok(())
}
