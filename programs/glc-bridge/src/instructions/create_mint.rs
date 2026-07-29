//! One-time creation of the wrapped-GLC SPL mint (ADR-0009).
//!
//! The mint's sole authority is the data-less mint-authority PDA (ADR-0004):
//! no keypair for it exists, and minting happens only via `invoke_signed`
//! inside the program's own checked mint path.
//!
//! Freeze authority is `None` — custody decision #6 (docs/custody.md):
//! the federation must not be able to freeze user funds. This is
//! irreversible for a given mint by design.
//!
//! Classic SPL Token program, decimals fixed at `WRAPPED_GLC_DECIMALS`.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token};

use crate::constants::{SEED_BRIDGE_CONFIG, SEED_MINT_AUTHORITY, WRAPPED_GLC_DECIMALS};
use crate::errors::BridgeError;
use crate::events::WrappedMintCreated;
use crate::state::BridgeConfig;

#[derive(Accounts)]
pub struct CreateWrappedMint<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [SEED_BRIDGE_CONFIG],
        bump = bridge_config.bump,
        constraint = bridge_config.admin == admin.key() @ BridgeError::UnauthorizedAdmin,
        constraint = bridge_config.wrapped_mint == Pubkey::default()
            @ BridgeError::MintAlreadyConfigured
    )]
    pub bridge_config: Account<'info, BridgeConfig>,

    /// CHECK: data-less PDA; never holds data or lamports, only signs mints
    /// via `invoke_signed` (ADR-0004). Address is fully constrained by seeds.
    #[account(seeds = [SEED_MINT_AUTHORITY], bump)]
    pub mint_authority: UncheckedAccount<'info>,

    /// The wrapped-GLC mint, created here. A fresh keypair signs its own
    /// creation; the address is then fixed forever in `bridge_config`.
    /// `freeze_authority` is intentionally absent => None (custody #6).
    #[account(
        init,
        payer = admin,
        mint::decimals = WRAPPED_GLC_DECIMALS,
        mint::authority = mint_authority,
    )]
    pub wrapped_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn create_wrapped_mint(ctx: Context<CreateWrappedMint>) -> Result<()> {
    let config = &mut ctx.accounts.bridge_config;
    config.wrapped_mint = ctx.accounts.wrapped_mint.key();
    config.mint_authority_bump = ctx.bumps.mint_authority;

    emit!(WrappedMintCreated {
        mint: config.wrapped_mint,
        mint_authority: ctx.accounts.mint_authority.key(),
        decimals: WRAPPED_GLC_DECIMALS,
    });
    Ok(())
}
