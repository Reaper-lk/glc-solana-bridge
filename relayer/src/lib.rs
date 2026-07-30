//! `glc-relayer` library surface.
//!
//! Exists so integration tests (`tests/regtest_indexer.rs`) can exercise the
//! real indexer/db/rpc/deposit code against a live Goldcoin node exactly as
//! `main.rs` does, rather than duplicating it. `main.rs` is a thin
//! environment-wiring binary over this library.

pub mod glc;
pub mod p2p;
pub mod signer;
pub mod solana;
