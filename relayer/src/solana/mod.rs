//! Solana side — placeholder, implemented in Phase 5.
//!
//! Planned:
//! - RPC client + transaction builder for `mint_wrapped` submissions carrying
//!   the aggregated federation proof;
//! - withdrawal watcher that scans persistent `WithdrawalRequest` program
//!   accounts (paginated `getProgramAccounts`). Event subscriptions may be
//!   used to reduce latency but are NEVER the source of truth — accounts are
//!   recoverable after downtime, event streams are not.
