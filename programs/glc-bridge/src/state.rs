//! Program account state — Phase 0 placeholders.
//!
//! Structs are intentionally EMPTY: field layout is a Phase 1 deliverable and
//! freezing it now, uncompiled and unreviewed, would only create churn. The
//! doc comments record the agreed design so Phase 1 implements to spec.

use anchor_lang::prelude::*;

/// Singleton bridge configuration (PDA: [`crate::constants::SEED_BRIDGE_CONFIG`]).
///
/// Phase 1 fields (planned):
/// - `admin: Pubkey` — governance authority (custody model unresolved, see docs/custody.md)
/// - `wrapped_mint: Pubkey`
/// - `validators: Vec<Pubkey>` + `threshold: u8` — federation set, M-of-N
/// - `paused: bool` — circuit breaker checked by mint/burn paths
/// - `withdrawal_count: u64` — seed counter for withdrawal PDAs
/// - `min_deposit: u64`, `min_withdrawal: u64` — dust/DoS floors
#[account]
pub struct BridgeConfig {}

/// One processed Goldcoin deposit (PDA: [`crate::constants::SEED_DEPOSIT_CLAIM`]
/// + `txid` + `vout`). The account's existence is the replay guard: a second
/// `mint_wrapped` for the same `(txid, vout)` fails at account creation.
///
/// Phase 2 fields (planned): `txid: [u8; 32]`, `vout: u32`, `amount: u64`,
/// `recipient: Pubkey`, `minted_at_slot: u64`.
#[account]
pub struct DepositClaim {}

/// Persistent withdrawal record (PDA: [`crate::constants::SEED_WITHDRAWAL`]
/// + index). Created by `burn_wrapped`; the authoritative source relayers
/// scan — NOT the event stream. Schema stays signing-agnostic so the later
/// vault-custody decision (docs/custody.md) doesn't force a migration.
///
/// Phase 3 fields (planned): `index: u64`, `amount: u64`,
/// `glc_address: [u8; 25]` (format verified in Phase 2), `requested_at_slot: u64`,
/// `status: WithdrawalStatus` (`Pending → Broadcast → Completed`).
#[account]
pub struct WithdrawalRequest {}
