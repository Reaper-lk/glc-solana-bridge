//! PDA seed constants. Fixed in Phase 0 so every later phase and every
//! off-chain component derives addresses identically from day one.

/// Singleton bridge configuration account.
pub const SEED_BRIDGE_CONFIG: &[u8] = b"bridge_config";

/// PDA that holds mint (and, if retained, freeze) authority over the wrapped
/// mint. The program signs mints via `invoke_signed`; no keypair exists.
pub const SEED_MINT_AUTHORITY: &[u8] = b"mint_authority";

/// Per-deposit claim PDA, additionally seeded with the Goldcoin deposit
/// identity `(txid: [u8; 32], vout: u32 little-endian)`. Existence of this
/// account IS the replay guard.
pub const SEED_DEPOSIT_CLAIM: &[u8] = b"deposit_claim";

/// Per-withdrawal record PDA, additionally seeded with a monotonically
/// increasing withdrawal index from `BridgeConfig`.
pub const SEED_WITHDRAWAL: &[u8] = b"withdrawal";

/// Wrapped-token decimals. Provisional: assumed equal to native GLC's 8;
/// verified against Goldcoin Core source in Phase 2 (docs/goldcoin-rpc-notes.md).
pub const WRAPPED_GLC_DECIMALS: u8 = 8;
