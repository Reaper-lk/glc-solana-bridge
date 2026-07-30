//! Goldcoin withdrawal executor (Phase 6, ADR-0013).
//!
//! Observes finalized `WithdrawalRequest` accounts on Solana, selects vault
//! UTXOs, builds and verifies a native Goldcoin payout, signs it, broadcasts
//! it, tracks confirmations, and reconciles — restart-safe, reorg-safe, and
//! structurally unable to pay twice.
//!
//! # ⚠️ Regtest bootstrap custody — NOT production
//!
//! Owner decision D2: the vault is a single-key P2PKH address whose key is
//! held by the Goldcoin node wallet. This is the withdrawal-side analogue of
//! Phase 5's R2 bootstrap topology and carries the same warning: one key can
//! drain the vault, and there is no threshold, no multisig, and no key
//! ceremony. custody.md #2 (vault construction) and #3 (signing model)
//! remain OPEN. Do not deploy this beyond a controlled regtest environment.

pub mod address;
pub mod builder;
pub mod coin;
pub mod config;
pub mod discovery;
pub mod executor;
