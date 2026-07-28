//! Cryptographic verification helpers — INTENTIONALLY EMPTY in Phase 0.
//!
//! Phase 3 adds verification utilities for the federation's aggregated
//! M-of-N proof (encoding decided in Phase 3; see
//! docs/adr/0005-offchain-signature-aggregation.md).
//!
//! Hard rules for this module, at every phase:
//! - verification only — key generation, signing, and key storage NEVER live
//!   in shared code reachable from the on-chain program;
//! - no `rand`, no OS entropy, no key material of any kind.
