//! Inter-relayer network: federation signature exchange (Phase 7c/7d,
//! ADR-0016).
//!
//! Carries signature exchange between federation members over mutually
//! authenticated gRPC (tonic); libp2p was rejected in ADR-0014 §6.1 as
//! unneeded surface for a fixed, known peer set.
//!
//! The Phase 0 design constraints recorded here are now implemented rather
//! than aspirational:
//!
//! - **mutually authenticated channels between registered validators only** —
//!   identity is bound twice, at the transport by mTLS against a pinned
//!   federation CA ([`identity`]) and at the application by the on-chain
//!   ed25519 validator key every response is checked against
//!   ([`collector`]). Neither alone is sufficient, which is the point: a
//!   stolen certificate still cannot impersonate a validator;
//! - **no consensus of its own** — the Goldcoin chain and the Anchor
//!   program's threshold check remain the only arbiters. See
//!   [`policy::evaluate`]: a responder re-derives every message from its own
//!   observations ([`view`]) and refuses anything it cannot independently
//!   confirm, so this layer moves signatures, never truth;
//! - **a lagging peer catches up from chain state alone** — nothing here is
//!   a source of record, and a validator that has not itself observed a
//!   deposit simply refuses to sign for it. A validator that has stopped
//!   observing altogether refuses everything ([`policy::Refusal::StaleView`])
//!   rather than answering from memory.
//!
//! # Module map
//!
//! | module | responsibility |
//! |---|---|
//! | [`policy`] | whether to sign, and over which bytes — no I/O |
//! | [`view`] | what this validator independently derives, from its own DB |
//! | [`service`] | the signer server: transport plus the single key |
//! | [`identity`] | peer identity and pinned TLS material |
//! | [`aggregation`] | who to ask, how long to wait, when a round is done |
//! | [`collector`] | the client: mTLS, timeouts, failover |
//! | [`ratelimit`] | per-peer request limits, so one peer cannot starve the rest |
//! | [`payout_view`] | what this validator will sign for a vault payout (7e) |
//! | [`completion_view`] | what this validator will attest a completion for (7f) |
//! | [`governance_view`] | what this validator will sign for governance — operator-staged, not derived (7i-0) |
//! | [`sweep_view`] | what this validator will sign for a vault sweep — operator-staged, plus its own UTXO view (7i-0) |

pub mod aggregation;
pub mod collector;
pub mod completion_view;
pub mod governance_view;
pub mod identity;
pub mod payout_view;
pub mod policy;
pub mod ratelimit;
pub mod service;
pub mod sweep_view;
pub mod view;
