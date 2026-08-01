//! Goldcoin withdrawal executor (Phase 6, ADR-0013).
//!
//! Observes finalized `WithdrawalRequest` accounts on Solana, selects vault
//! UTXOs, builds and verifies a native Goldcoin payout, signs it, broadcasts
//! it, tracks confirmations, and reconciles — restart-safe, reorg-safe, and
//! structurally unable to pay twice.
//!
//! # Custody
//!
//! The vault is a **P2SH M-of-N multisig** (ADR-0015, ADR-0017): no single
//! process holds enough key material to spend it, and each designated signer
//! signs on its own Goldcoin node against its own UTXO view.
//!
//! This header previously described the Phase 6 bootstrap: a single-key
//! P2PKH vault held by the node wallet (owner decision D2). That vault was
//! deleted in Phase 7e — `config::WithdrawalConfig` now refuses to validate
//! anything but a multisig redeem script — and the warning is removed here
//! rather than left standing, because a stale custody warning is read as a
//! current one.

pub mod adapter;
pub mod address;
pub mod assignment;
pub mod builder;
pub mod coin;
pub mod completion;
pub mod config;
pub mod discovery;
pub mod executor;
pub mod federation;
pub mod multisig;
pub mod status;
pub mod sweep;
pub mod vault;
