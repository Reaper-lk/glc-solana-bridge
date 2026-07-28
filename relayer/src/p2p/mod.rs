//! Inter-relayer network — placeholder, implemented in Phase 5.
//!
//! Carries signature aggregation between federation members (blueprint
//! specifies gRPC or libp2p; transport chosen in Phase 5). Design
//! constraints recorded now:
//! - mutually authenticated channels between registered validators only;
//! - no consensus of its own — the Goldcoin chain plus the Anchor program's
//!   threshold check are the arbiters; this layer only moves signatures;
//! - a lagging peer must be able to catch up from chain state alone.
