//! # glc-bridge-shared
//!
//! Single source of truth for data structures used by BOTH the on-chain
//! program (`programs/glc-bridge`) and the off-chain relayer (`relayer/`),
//! so their byte-level views of deposits, withdrawals, and federation
//! payloads can never drift apart.
//!
//! This crate must always remain SBF-compatible: no async, no I/O, no
//! networking, no randomness. See Cargo.toml for the dependency policy.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod types;
