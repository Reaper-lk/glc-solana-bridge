//! # glc-bridge — Solana side of the Goldcoin federated bridge
//!
//! **Phase 0 placeholder.** No bridge logic is implemented. This crate exists
//! so the workspace, Anchor project, and CI are wired end-to-end before any
//! value-bearing code is written.
//!
//! ## Planned instruction set (see docs/architecture.md)
//! - `initialize` — create [`state::BridgeConfig`], the wrapped-GLC mint, and
//!   the PDA mint authority. (Phase 1)
//! - `mint_wrapped` — verify an M-of-N aggregated federation proof for a
//!   deposit identified by Goldcoin `(txid, vout)`, create the per-claim
//!   [`state::DepositClaim`] PDA (replay guard), mint 1:1. (Phases 2–3)
//! - `burn_wrapped` — burn wrapped GLC and create a persistent
//!   [`state::WithdrawalRequest`] PDA; events are emitted as a convenience
//!   but the account record is authoritative. (Phase 3)
//! - admin instructions — pause flag, validator-set / threshold updates,
//!   governance-gated. (Phase 1)

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod events;
pub mod state;

declare_id!("77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq");

#[program]
pub mod glc_bridge {
    use super::*;

    /// Phase 0 scaffold check: proves the program compiles, deploys to a
    /// localnet, and is callable. Removed when real instructions land.
    pub fn ping(_ctx: Context<Ping>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Ping {}
