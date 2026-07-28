//! Goldcoin L1 side — placeholder, implemented in Phases 2 and 4.
//!
//! Planned submodules:
//! - `rpc` — thin typed JSON-RPC client for Goldcoin Core. Hand-rolled rather
//!   than `bitcoincore-rpc`, because Goldcoin is a ~0.14-era Bitcoin fork and
//!   modern RPC shapes won't match (verified facts go in
//!   docs/goldcoin-rpc-notes.md).
//! - `indexer` — block-by-block scanner: vault-deposit detection keyed by
//!   `(txid, vout)`, confirmation-depth tracking, reorg detection with
//!   rollback of not-yet-signed observations.
//!
//! Rule: claim signing only ever consumes CONFIRMED blocks at the required
//! depth. Mempool data is never an input to signing.
