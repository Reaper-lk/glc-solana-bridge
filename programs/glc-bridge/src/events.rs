//! Anchor events.
//!
//! Design rule (docs/adr/0006): events are a UX/indexing convenience ONLY.
//! Anything the bridge must not lose — above all withdrawal requests — is
//! stored in persistent accounts (`state::WithdrawalRequest`), because Solana
//! log delivery is best-effort and logs are truncated/pruned.
//!
//! Planned (Phase 2–3):
//! - `DepositMinted { deposit_txid, vout, amount, recipient }`
//! - `WithdrawalRequested { withdrawal_index, amount, glc_address }`
//!
//! No events are defined in Phase 0.
