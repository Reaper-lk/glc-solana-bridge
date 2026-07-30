//! Goldcoin L1 side (ADR-0011, Phase 4).
//!
//! - `rpc` — thin typed JSON-RPC client for Goldcoin Core. Hand-rolled
//!   rather than `bitcoincore-rpc`, because Goldcoin's RPC shapes diverge
//!   from modern Bitcoin Core (verified facts: docs/goldcoin-rpc-notes.md —
//!   `getblock` takes only a boolean verbosity, `getrawtransaction` needs
//!   `-txindex=1`, no blockhash-hint parameter exists).
//! - `db` — persistent, transactional indexer state (SQLite/rusqlite).
//! - `deposit` — pure vault-matching, OP_RETURN extraction, and canonical
//!   claim-message construction; no I/O, fully unit-testable.
//! - `indexer` — the tick loop tying `rpc` + `db` + `deposit` together:
//!   forward indexing, reorg detection/rollback, state-machine transitions.
//! - `config` — validated operator configuration.
//! - `hex` — minimal shared hex codec.
//!
//! Rule: claim signing only ever consumes CONFIRMED blocks at the required
//! depth. Mempool data is never an input to signing. Phase 4 produces only
//! unsigned canonical claim artifacts — no signing, no p2p, no Solana
//! submission (Phase 5+).

pub mod config;
pub mod db;
pub mod deposit;
pub mod hex;
pub mod indexer;
pub mod rpc;
