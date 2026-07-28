//! Key management & claim signing — placeholder.
//!
//! OUT OF SCOPE for Phase 0 by explicit project decision: no signing logic,
//! no key handling, no TSS, no vault (GLC payout) signing. The vault custody
//! model itself is unresolved — see docs/custody.md — and this module must
//! not pre-empt that decision.
//!
//! When implemented (Phase 3+): loads this validator's federation identity
//! from an operator-provided keystore (never from the repository), signs
//! `InboundClaim` payloads, and contributes to M-of-N aggregation.
