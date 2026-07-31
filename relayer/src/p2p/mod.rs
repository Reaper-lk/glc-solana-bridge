//! Inter-relayer network: federation signature exchange (Phase 7c,
//! ADR-0016).
//!
//! Carries signature exchange between federation members. Transport is gRPC
//! (tonic); libp2p was rejected in ADR-0014 §6.1 as unneeded surface for a
//! fixed, known peer set.
//!
//! The Phase 0 design constraints recorded here are now implemented rather
//! than aspirational:
//!
//! - **mutually authenticated channels between registered validators only** —
//!   peers are identified by their on-chain ed25519 validator key, and an
//!   unknown peer is refused;
//! - **no consensus of its own** — the Goldcoin chain and the Anchor
//!   program's threshold check remain the only arbiters. See
//!   [`policy::evaluate`]: a responder re-derives every message from its own
//!   observations and refuses anything it cannot independently confirm, so
//!   this layer moves signatures, never truth;
//! - **a lagging peer catches up from chain state alone** — nothing here is
//!   a source of record, and a validator that has not itself observed a
//!   deposit simply refuses to sign for it.

pub mod policy;
pub mod service;

/// A [`SignatureCollector`](crate::orchestrator::SignatureCollector) backed
/// by federation peers over gRPC.
///
/// Phase 7c ships the protocol, the policy, and the service. Wiring a
/// multi-peer client pool with mTLS is the remaining transport work; until
/// then this collector talks to a configured set of signer endpoints and
/// returns whatever they produce, so the orchestrator's contract — "I hold
/// no keys, I ask for signatures" — is already the real one.
pub mod collector;
