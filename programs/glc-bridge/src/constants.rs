//! PDA seed constants and protocol-wide limits. Fixed in Phase 0/1 so every
//! later phase and every off-chain component derives addresses identically
//! from day one.

/// Singleton bridge configuration account.
pub const SEED_BRIDGE_CONFIG: &[u8] = b"bridge_config";

/// Singleton federation validator-set account (ADR-0007). The epoch is a
/// field inside the account, not a seed: the address never changes across
/// validator-set rotations.
pub const SEED_VALIDATOR_SET: &[u8] = b"validator_set";

/// PDA that holds mint (and, if retained, freeze) authority over the wrapped
/// mint. The program signs mints via `invoke_signed`; no keypair exists.
/// The mint itself is created in Phase 2, not at `initialize` (ADR-0008).
pub const SEED_MINT_AUTHORITY: &[u8] = b"mint_authority";

/// Per-deposit claim PDA, additionally seeded with the Goldcoin deposit
/// identity `(txid: [u8; 32], vout: u32 little-endian)`. Existence of this
/// account IS the replay guard.
pub const SEED_DEPOSIT_CLAIM: &[u8] = b"deposit_claim";

/// Singleton PDA holding the governance action currently inside its
/// timelock window (Phase 7a, ADR-0014). At most one may be pending.
pub const SEED_GOVERNANCE_ACTION: &[u8] = b"governance_action";

/// Per-withdrawal record PDA, additionally seeded with a monotonically
/// increasing withdrawal index from `BridgeConfig`.
pub const SEED_WITHDRAWAL: &[u8] = b"withdrawal";

/// Version of the on-chain state layout / protocol semantics, stored in
/// [`crate::state::BridgeConfig`]. Bumped on any breaking change to account
/// layouts or instruction semantics, so off-chain components can refuse to
/// operate against a version they do not understand.
pub const PROTOCOL_VERSION: u8 = 1;

/// Hard cap on the number of federation validators (N).
///
/// Rationale: `ValidatorSet` is allocated once at maximum size (ADR-0007),
/// so the cap bounds rent up front; more importantly, Phase 3's on-chain
/// M-of-N proof verification must fit N signature checks into one
/// transaction's compute/precompile budget (ADR-0005). 16 is comfortably
/// within both and larger than any federation composition under discussion
/// (docs/custody.md #1). Raising it is a `PROTOCOL_VERSION` bump.
pub const MAX_VALIDATORS: usize = 16;

/// Wrapped-token decimals. Provisional: assumed equal to native GLC's 8;
/// verified against Goldcoin Core source in Phase 4 (docs/goldcoin-rpc-notes.md).
pub const WRAPPED_GLC_DECIMALS: u8 = 8;

/// Maximum byte length of the opaque ASCII Goldcoin destination address
/// stored in a `WithdrawalRequest`. Generous for base58 (26–35 chars for a
/// ~Bitcoin-0.14-era chain) plus headroom; the real format is verified in
/// Phase 4 and semantic validation added then (docs/goldcoin-rpc-notes.md).
pub const MAX_GLC_ADDRESS_LEN: usize = 64;
