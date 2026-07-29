//! Program account state.
//!
//! Every account documents its byte layout exactly; the `SPACE` constants are
//! the single source of truth for allocation and are asserted against real
//! borsh serialization in unit tests (`space` module below). Any layout
//! change here is a `PROTOCOL_VERSION` bump and a documentation update
//! (docs/architecture.md, ADR-0007/0008).

use anchor_lang::prelude::*;

use crate::constants::MAX_VALIDATORS;

/// Singleton bridge configuration (PDA: [`crate::constants::SEED_BRIDGE_CONFIG`]).
///
/// Byte layout (borsh, after the 8-byte Anchor discriminator):
///
/// | field              | type           | bytes |
/// |--------------------|----------------|-------|
/// | `protocol_version` | `u8`           | 1     |
/// | `admin`            | `Pubkey`       | 32    |
/// | `pending_admin`    | `Option<Pubkey>` | 1 + 32 |
/// | `paused`           | `bool`         | 1     |
/// | `withdrawal_count` | `u64`          | 8     |
/// | `min_deposit`      | `u64`          | 8     |
/// | `min_withdrawal`   | `u64`          | 8     |
/// | `bump`             | `u8`           | 1     |
/// | `reserved`         | `[u8; 64]`     | 64    |
///
/// `Option<Pubkey>` is allocated at its maximum (`Some`) size so the account
/// never needs realloc. The wrapped mint's pubkey is deliberately NOT here
/// yet: the mint is created in Phase 2 (ADR-0008), and its field is added
/// then, taken out of `reserved`.
#[account]
pub struct BridgeConfig {
    /// [`crate::constants::PROTOCOL_VERSION`] at initialization; bumped by
    /// future migrations.
    pub protocol_version: u8,
    /// Governance authority for pause, validator-set updates, and admin
    /// handover. Interim single-key model — the custody decisions
    /// (docs/custody.md #1/#7) will replace or constrain it (ADR-0008).
    pub admin: Pubkey,
    /// Set by `transfer_admin`, consumed by `accept_admin` (two-step
    /// handover so a typoed key cannot brick governance).
    pub pending_admin: Option<Pubkey>,
    /// Circuit breaker. Checked by the mint/burn paths from Phase 2 on;
    /// admin instructions themselves remain callable while paused (otherwise
    /// un-pausing would be impossible).
    pub paused: bool,
    /// Monotonic seed counter for `WithdrawalRequest` PDAs (used from
    /// Phase 3).
    pub withdrawal_count: u64,
    /// Dust/DoS floor for deposits (enforced from Phase 2). 0 = disabled.
    pub min_deposit: u64,
    /// Dust/DoS floor for withdrawals (enforced from Phase 3). 0 = disabled.
    pub min_withdrawal: u64,
    /// Canonical PDA bump, stored so later phases never re-derive it.
    pub bump: u8,
    /// Expansion space for future fields (e.g. the Phase 2 `wrapped_mint`),
    /// so already-initialized deployments can migrate without moving
    /// accounts. Must be all zeroes until a migration assigns meaning.
    pub reserved: [u8; 64],
}

impl BridgeConfig {
    /// 8 (discriminator) + 1 + 32 + 33 + 1 + 8 + 8 + 8 + 1 + 64 = 164.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 1 // protocol_version
        + 32 // admin
        + (1 + 32) // pending_admin (Option tag + Pubkey)
        + 1 // paused
        + 8 // withdrawal_count
        + 8 // min_deposit
        + 8 // min_withdrawal
        + 1 // bump
        + 64; // reserved
}

/// Singleton federation validator set (PDA:
/// [`crate::constants::SEED_VALIDATOR_SET`], ADR-0007).
///
/// Byte layout (borsh, after the 8-byte Anchor discriminator):
///
/// | field        | type          | bytes            |
/// |--------------|---------------|------------------|
/// | `epoch`      | `u64`         | 8                |
/// | `threshold`  | `u8`          | 1                |
/// | `bump`       | `u8`          | 1                |
/// | `validators` | `Vec<Pubkey>` | 4 + 32 × len     |
/// | `reserved`   | `[u8; 32]`    | 32               |
///
/// The account is allocated once at `MAX_VALIDATORS` capacity so
/// `update_validator_set` never reallocs, and the rent cost is fixed at
/// initialization.
#[account]
pub struct ValidatorSet {
    /// Revision counter, starting at 0 and incremented (checked) on every
    /// `update_validator_set`. Phase 3 proofs bind to the epoch they were
    /// signed under, so a rotation invalidates in-flight proofs.
    pub epoch: u64,
    /// M of M-of-N: minimum validator signatures for a federation action.
    /// Invariant (enforced on every write): `1 <= threshold <= validators.len()`.
    pub threshold: u8,
    /// Canonical PDA bump, stored so later phases never re-derive it.
    pub bump: u8,
    /// Federation member public keys (ed25519). Invariants (enforced on
    /// every write): non-empty, no duplicates, no all-zero (default) keys —
    /// which cannot sign and would make the threshold unreachable —
    /// `len() <= MAX_VALIDATORS`.
    pub validators: Vec<Pubkey>,
    /// Expansion space for future fields. Must be all zeroes until a
    /// migration assigns meaning.
    pub reserved: [u8; 32],
}

impl ValidatorSet {
    /// 8 (discriminator) + 8 + 1 + 1 + (4 + 32×16) + 32 = 566.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 8 // epoch
        + 1 // threshold
        + 1 // bump
        + (4 + 32 * MAX_VALIDATORS) // validators (Vec length prefix + keys)
        + 32; // reserved
}

/// One processed Goldcoin deposit (PDA: [`crate::constants::SEED_DEPOSIT_CLAIM`]
/// + `txid` + `vout`). The account's existence is the replay guard: a second
/// `mint_wrapped` for the same `(txid, vout)` fails at account creation.
///
/// Phase 2 fields (planned): `txid: [u8; 32]`, `vout: u32`, `amount: u64`,
/// `recipient: Pubkey`, `minted_at_slot: u64`.
#[account]
pub struct DepositClaim {}

/// Persistent withdrawal record (PDA: [`crate::constants::SEED_WITHDRAWAL`]
/// + index). Created by `burn_wrapped`; the authoritative source relayers
/// scan — NOT the event stream. Schema stays signing-agnostic so the later
/// vault-custody decision (docs/custody.md) doesn't force a migration.
///
/// Phase 3 fields (planned): `index: u64`, `amount: u64`,
/// `glc_address: [u8; 25]` (format verified in Phase 2), `requested_at_slot: u64`,
/// `status: WithdrawalStatus` (`Pending → Broadcast → Completed`).
#[account]
pub struct WithdrawalRequest {}

/// The `SPACE` constants above are hand-written arithmetic; these tests pin
/// them to what borsh actually produces for maximally-populated values, so a
/// field edit that forgets the constant fails loudly.
#[cfg(test)]
mod space {
    use super::*;

    #[test]
    fn bridge_config_space_matches_serialized_max() {
        let max = BridgeConfig {
            protocol_version: u8::MAX,
            admin: Pubkey::new_unique(),
            pending_admin: Some(Pubkey::new_unique()), // Option at max size
            paused: true,
            withdrawal_count: u64::MAX,
            min_deposit: u64::MAX,
            min_withdrawal: u64::MAX,
            bump: u8::MAX,
            reserved: [0u8; 64],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), BridgeConfig::SPACE);
        assert_eq!(BridgeConfig::SPACE, 164);
    }

    #[test]
    fn validator_set_space_matches_serialized_max() {
        let max = ValidatorSet {
            epoch: u64::MAX,
            threshold: u8::MAX,
            bump: u8::MAX,
            validators: vec![Pubkey::new_unique(); MAX_VALIDATORS],
            reserved: [0u8; 32],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), ValidatorSet::SPACE);
        assert_eq!(ValidatorSet::SPACE, 566);
    }
}
