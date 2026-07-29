//! # glc-bridge — Solana side of the Goldcoin federated bridge
//!
//! **Phase 1: bridge state and governance.** [`state::BridgeConfig`] and
//! [`state::ValidatorSet`] PDAs, upgrade-authority-gated initialization
//! (ADR-0008), pause circuit breaker, epoch-tracked validator-set rotation
//! (ADR-0007), and two-step admin handover. No value moves in this phase:
//! the wrapped mint, deposits, and withdrawals land in Phases 2–3.
//!
//! ## Instruction set
//! - [`initialize`](glc_bridge::initialize) — create the two state PDAs;
//!   only the program upgrade authority may call, exactly once. (Phase 1)
//! - [`set_paused`](glc_bridge::set_paused),
//!   [`update_validator_set`](glc_bridge::update_validator_set),
//!   [`transfer_admin`](glc_bridge::transfer_admin) /
//!   [`accept_admin`](glc_bridge::accept_admin) — admin-gated governance.
//!   (Phase 1)
//! - `mint_wrapped` — verify an M-of-N aggregated federation proof for a
//!   deposit identified by Goldcoin `(txid, vout)`, create the per-claim
//!   [`state::DepositClaim`] PDA (replay guard), mint 1:1. (Phases 2–3)
//! - `burn_wrapped` — burn wrapped GLC and create a persistent
//!   [`state::WithdrawalRequest`] PDA; events are emitted as a convenience
//!   but the account record is authoritative. (Phase 3)

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;
pub mod validation;

use instructions::*;

declare_id!("77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq");

#[program]
pub mod glc_bridge {
    use super::*;

    /// One-time creation of [`state::BridgeConfig`] and
    /// [`state::ValidatorSet`]. Caller must be the program upgrade authority
    /// and becomes the initial admin.
    pub fn initialize(
        ctx: Context<Initialize>,
        validators: Vec<Pubkey>,
        threshold: u8,
        min_deposit: u64,
        min_withdrawal: u64,
    ) -> Result<()> {
        instructions::initialize(ctx, validators, threshold, min_deposit, min_withdrawal)
    }

    /// Admin-only circuit breaker for the value-moving paths (Phase 2+).
    pub fn set_paused(ctx: Context<AdminConfig>, paused: bool) -> Result<()> {
        instructions::set_paused(ctx, paused)
    }

    /// Admin-only validator-set/threshold rotation; advances the epoch.
    pub fn update_validator_set(
        ctx: Context<UpdateValidatorSet>,
        validators: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        instructions::update_validator_set(ctx, validators, threshold)
    }

    /// Admin-only step 1 of the two-step admin handover.
    pub fn transfer_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
        instructions::transfer_admin(ctx, new_admin)
    }

    /// Step 2 of the handover; only the pending admin may call.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        instructions::accept_admin(ctx)
    }

    /// One-time creation of the wrapped-GLC SPL mint; admin-only. Mint
    /// authority is the mint-authority PDA, freeze authority is None
    /// (custody #6, ADR-0009).
    pub fn create_wrapped_mint(ctx: Context<CreateWrappedMint>) -> Result<()> {
        instructions::create_wrapped_mint(ctx)
    }

    /// TEMPORARY Phase 2 test scaffolding: the deposit-claim mint path with
    /// admin-signature authorization instead of federation proof
    /// verification. Deleted in Phase 3 (ADR-0009); see the module docs in
    /// [`instructions::mint_testonly`].
    pub fn mint_wrapped_testonly(
        ctx: Context<MintWrappedTestonly>,
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        epoch: u64,
    ) -> Result<()> {
        instructions::mint_wrapped_testonly(ctx, txid, vout, amount, epoch)
    }
}
