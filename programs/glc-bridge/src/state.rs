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
/// | `wrapped_mint`     | `Pubkey`       | 32    |
/// | `mint_authority_bump` | `u8`        | 1     |
/// | `reserved`         | `[u8; 31]`     | 31    |
///
/// `Option<Pubkey>` is allocated at its maximum (`Some`) size so the account
/// never needs realloc. Phase 2 consumed 33 bytes of the original 64-byte
/// reserve for `wrapped_mint` + `mint_authority_bump`, appended after `bump`
/// so every pre-existing field keeps its byte offset (ADR-0009); total size
/// is unchanged.
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
    /// The wrapped-GLC SPL mint, set once by `create_wrapped_mint`.
    /// `Pubkey::default()` means "not yet created" — every mint path
    /// explicitly rejects that sentinel (`MintNotConfigured`).
    pub wrapped_mint: Pubkey,
    /// Canonical bump of the mint-authority PDA
    /// ([`crate::constants::SEED_MINT_AUTHORITY`]), stored at
    /// `create_wrapped_mint` for `invoke_signed`.
    pub mint_authority_bump: u8,
    /// Delay, in seconds, between proposing a governance action and its
    /// earliest execution (Phase 7a, ADR-0014). Set at `initialize` with no
    /// built-in default — the safe value is a live security/ops decision
    /// (custody.md #7), and the program refuses to run on a zero.
    ///
    /// Appended AFTER `mint_authority_bump` and taken out of `reserved`, so
    /// every pre-existing field keeps its byte offset and the account's
    /// total size is unchanged (the same discipline ADR-0009 used).
    pub governance_timelock_seconds: i64,
    /// Expansion space for future fields, so already-initialized deployments
    /// can migrate without moving accounts. Must be all zeroes until a
    /// migration assigns meaning.
    pub reserved: [u8; 23],
}

impl BridgeConfig {
    /// 8 (discriminator) + 1 + 32 + 33 + 1 + 8 + 8 + 8 + 1 + 32 + 1 + 8 + 23
    /// = 164 — unchanged by Phase 7a, which took its field out of `reserved`.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 1 // protocol_version
        + 32 // admin
        + (1 + 32) // pending_admin (Option tag + Pubkey)
        + 1 // paused
        + 8 // withdrawal_count
        + 8 // min_deposit
        + 8 // min_withdrawal
        + 1 // bump
        + 32 // wrapped_mint
        + 1 // mint_authority_bump
        + 8 // governance_timelock_seconds
        + 23; // reserved
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

/// A governance action that has been threshold-approved but is still inside
/// its timelock window (PDA: [`crate::constants::SEED_GOVERNANCE_ACTION`],
/// Phase 7a, ADR-0014).
///
/// A **singleton**: at most one action may be pending at a time. That is
/// deliberate — it keeps the queue trivially auditable (an observer checks
/// one address), makes "what is about to happen to this bridge?" a single
/// account read, and prevents an attacker who briefly holds threshold from
/// flooding a backlog of actions that all mature later. Replacing a pending
/// action requires an explicit, threshold-approved cancellation first.
///
/// The account is allocated at `MAX_VALIDATORS` capacity so a proposal never
/// reallocs, exactly as [`ValidatorSet`] is.
///
/// Byte layout (borsh, after the 8-byte Anchor discriminator):
///
/// | field                  | type          | bytes        |
/// |------------------------|---------------|--------------|
/// | `action`               | `u8`          | 1            |
/// | `proposed_under_epoch` | `u64`         | 8            |
/// | `eta`                  | `i64`         | 8            |
/// | `threshold`            | `u8`          | 1            |
/// | `validators`           | `Vec<Pubkey>` | 4 + 32 × len |
/// | `bump`                 | `u8`          | 1            |
/// | `reserved`             | `[u8; 32]`    | 32           |
#[account]
pub struct PendingGovernanceAction {
    /// Action discriminant from `glc_bridge_shared::governance`
    /// (`ACTION_PROPOSE_ROTATION`). Stored so a future action type cannot be
    /// executed by a handler that was written for a different one.
    pub action: u8,
    /// The validator-set epoch this proposal was signed under. Execution
    /// requires the epoch to still match: a proposal approved by one
    /// federation must never be applied by a different one.
    pub proposed_under_epoch: u64,
    /// Earliest Unix timestamp at which execution is permitted.
    pub eta: i64,
    /// Proposed threshold.
    pub threshold: u8,
    /// Proposed validator set, in the exact order it will be stored. Order
    /// is part of the signed commitment.
    pub validators: Vec<Pubkey>,
    /// Canonical PDA bump.
    pub bump: u8,
    /// Expansion space. Must be all zeroes until a migration assigns meaning.
    pub reserved: [u8; 32],
}

impl PendingGovernanceAction {
    /// 8 (discriminator) + 1 + 8 + 8 + 1 + (4 + 32×16) + 1 + 32 = 575.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 1 // action
        + 8 // proposed_under_epoch
        + 8 // eta
        + 1 // threshold
        + (4 + 32 * MAX_VALIDATORS) // validators
        + 1 // bump
        + 32; // reserved
}

/// One processed Goldcoin deposit (PDA: [`crate::constants::SEED_DEPOSIT_CLAIM`]
/// + `txid` + `vout.to_le_bytes()`). The account's existence is the replay
/// guard (ADR-0003): a second mint for the same `(txid, vout)` fails at
/// account creation. Doubles as the permanent audit record of the deposit.
///
/// Byte layout (borsh, after the 8-byte Anchor discriminator):
///
/// | field              | type        | bytes |
/// |--------------------|-------------|-------|
/// | `txid`             | `[u8; 32]`  | 32    |
/// | `vout`             | `u32`       | 4     |
/// | `amount`           | `u64`       | 8     |
/// | `recipient`        | `Pubkey`    | 32    |
/// | `epoch`            | `u64`       | 8     |
/// | `protocol_version` | `u8`        | 1     |
/// | `slot_created`     | `u64`       | 8     |
/// | `bump`             | `u8`        | 1     |
/// | `reserved`         | `[u8; 16]`  | 16    |
#[account]
pub struct DepositClaim {
    /// Goldcoin transaction id, 32 bytes used VERBATIM as supplied in the
    /// claim — the program never reorders bytes. Canonical convention is
    /// Goldcoin internal (little-endian) byte order per `shared::DepositId`;
    /// verified against real node RPC output in Phase 4
    /// (docs/goldcoin-rpc-notes.md).
    pub txid: [u8; 32],
    /// Output index within the transaction (ADR-0002).
    pub vout: u32,
    /// Minted amount in atomic GLC units (8 decimals, 1:1 with the deposit).
    pub amount: u64,
    /// Solana wallet the wrapped GLC was minted to (its associated token
    /// account for the wrapped mint received the tokens).
    pub recipient: Pubkey,
    /// Validator-set epoch (ADR-0007) this claim was authorized under.
    pub epoch: u64,
    /// `BridgeConfig.protocol_version` at mint time.
    pub protocol_version: u8,
    /// Solana slot in which the claim was created.
    pub slot_created: u64,
    /// Canonical PDA bump.
    pub bump: u8,
    /// Expansion space. Must be all zeroes until a migration assigns meaning.
    pub reserved: [u8; 16],
}

impl DepositClaim {
    /// 8 (discriminator) + 32 + 4 + 8 + 32 + 8 + 1 + 8 + 1 + 16 = 118.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 32 // txid
        + 4 // vout
        + 8 // amount
        + 32 // recipient
        + 8 // epoch
        + 1 // protocol_version
        + 8 // slot_created
        + 1 // bump
        + 16; // reserved
}

/// Lifecycle of a withdrawal record. Mirrors `shared::types::WithdrawalStatus`
/// — keep the two in sync. Borsh encodes the variant tag as one byte
/// (Pending = 0, Broadcast = 1, Completed = 2).
///
/// Phase 3 only ever writes `Pending`: the status write-back instructions
/// (and their authority model) are deliberately deferred until the payout
/// side exists (owner decision U2; ADR-0006 flagged this as
/// governance-relevant).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum WithdrawalStatus {
    /// Burn executed on Solana; GLC payout not yet broadcast.
    Pending,
    /// Payout transaction broadcast to the Goldcoin network.
    Broadcast,
    /// Payout confirmed at the required Goldcoin depth.
    Completed,
}

/// Persistent withdrawal record (PDA: [`crate::constants::SEED_WITHDRAWAL`]
/// + `index.to_le_bytes()`). Created atomically with the burn by
/// `burn_wrapped`; the authoritative payout-obligation record relayers scan
/// — NOT the event stream (ADR-0006). Schema stays signing-agnostic so the
/// later vault-custody decision (docs/custody.md) doesn't force a migration.
///
/// Byte layout (borsh, after the 8-byte Anchor discriminator):
///
/// | field               | type               | bytes |
/// |---------------------|--------------------|-------|
/// | `index`             | `u64`              | 8     |
/// | `amount`            | `u64`              | 8     |
/// | `requester`         | `Pubkey`           | 32    |
/// | `glc_address`       | `[u8; 64]`         | 64    |
/// | `glc_address_len`   | `u8`               | 1     |
/// | `status`            | `WithdrawalStatus` | 1     |
/// | `requested_at_slot` | `u64`              | 8     |
/// | `protocol_version`  | `u8`               | 1     |
/// | `bump`              | `u8`               | 1     |
/// | `reserved`          | `[u8; 48]`         | 48    |
#[account]
pub struct WithdrawalRequest {
    /// Monotonic index from `BridgeConfig.withdrawal_count`; also the PDA
    /// seed suffix.
    pub index: u64,
    /// Burned amount in atomic GLC units (8 decimals) — the payout
    /// obligation, gross of any future fee policy (custody.md #9).
    pub amount: u64,
    /// The wallet that burned; the payout dispute/audit anchor.
    pub requester: Pubkey,
    /// Opaque ASCII Goldcoin destination, left-justified, zero-padded.
    /// NOT semantically validated until the address format is verified
    /// against a real node in Phase 4 (owner decision U3).
    pub glc_address: [u8; 64],
    /// Number of meaningful bytes in `glc_address` (1..=64).
    pub glc_address_len: u8,
    /// Always `Pending` in Phase 3 (see enum docs).
    pub status: WithdrawalStatus,
    /// Solana slot in which the burn executed.
    pub requested_at_slot: u64,
    /// `BridgeConfig.protocol_version` at burn time.
    pub protocol_version: u8,
    /// Canonical PDA bump.
    pub bump: u8,
    /// Expansion space — sized so the future payout record (GLC payout txid
    /// 32B + confirmation slot/depth 8B) fits without migration. Must be all
    /// zeroes until a migration assigns meaning.
    pub reserved: [u8; 48],
}

impl WithdrawalRequest {
    /// 8 (discriminator) + 8 + 8 + 32 + 64 + 1 + 1 + 8 + 1 + 1 + 48 = 180.
    pub const SPACE: usize = 8 // Anchor discriminator
        + 8 // index
        + 8 // amount
        + 32 // requester
        + 64 // glc_address
        + 1 // glc_address_len
        + 1 // status
        + 8 // requested_at_slot
        + 1 // protocol_version
        + 1 // bump
        + 48; // reserved
}

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
            wrapped_mint: Pubkey::new_unique(),
            mint_authority_bump: u8::MAX,
            governance_timelock_seconds: i64::MAX,
            reserved: [0u8; 23],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), BridgeConfig::SPACE);
        assert_eq!(BridgeConfig::SPACE, 164);
    }

    /// The Phase 2 fields were appended after `bump` precisely so that every
    /// Phase 1 field keeps its byte offset (ADR-0009); this pins the offsets
    /// of the fields flanking the insertion point and the total length.
    /// Offsets are for the maximum-size (`pending_admin: Some`) encoding the
    /// account is allocated for, excluding the 8-byte discriminator:
    /// bump was — and stays — at body offset 91 (1+32+33+1+8+8+8).
    #[test]
    fn bridge_config_phase1_field_offsets_preserved() {
        let admin = Pubkey::new_unique();
        let wrapped_mint = Pubkey::new_unique();
        let config = BridgeConfig {
            protocol_version: 7,
            admin,
            pending_admin: Some(Pubkey::new_unique()),
            paused: false,
            withdrawal_count: 0,
            min_deposit: 0,
            min_withdrawal: 0,
            bump: 0xAB,
            wrapped_mint,
            mint_authority_bump: 0xCD,
            governance_timelock_seconds: 0,
            reserved: [0u8; 23],
        };
        let bytes = config.try_to_vec().unwrap();
        assert_eq!(bytes[0], 7, "protocol_version at offset 0");
        assert_eq!(&bytes[1..33], admin.as_ref(), "admin at offset 1");
        assert_eq!(
            bytes[91], 0xAB,
            "bump at offset 91 (unchanged from Phase 1)"
        );
        assert_eq!(
            &bytes[92..124],
            wrapped_mint.as_ref(),
            "wrapped_mint appended at offset 92"
        );
        assert_eq!(bytes[124], 0xCD, "mint_authority_bump at offset 124");
        assert_eq!(bytes.len(), BridgeConfig::SPACE - 8);
    }

    #[test]
    fn pending_governance_action_space_matches_serialized_max() {
        let max = PendingGovernanceAction {
            action: u8::MAX,
            proposed_under_epoch: u64::MAX,
            eta: i64::MAX,
            threshold: u8::MAX,
            validators: vec![Pubkey::new_unique(); MAX_VALIDATORS],
            bump: u8::MAX,
            reserved: [0u8; 32],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), PendingGovernanceAction::SPACE);
        assert_eq!(PendingGovernanceAction::SPACE, 575);
    }

    #[test]
    fn withdrawal_request_space_matches_serialized_max() {
        let max = WithdrawalRequest {
            index: u64::MAX,
            amount: u64::MAX,
            requester: Pubkey::new_unique(),
            glc_address: [u8::MAX; 64],
            glc_address_len: u8::MAX,
            status: WithdrawalStatus::Completed,
            requested_at_slot: u64::MAX,
            protocol_version: u8::MAX,
            bump: u8::MAX,
            reserved: [0u8; 48],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), WithdrawalRequest::SPACE);
        assert_eq!(WithdrawalRequest::SPACE, 180);
    }

    #[test]
    fn withdrawal_status_borsh_tags_are_stable() {
        assert_eq!(WithdrawalStatus::Pending.try_to_vec().unwrap(), vec![0]);
        assert_eq!(WithdrawalStatus::Broadcast.try_to_vec().unwrap(), vec![1]);
        assert_eq!(WithdrawalStatus::Completed.try_to_vec().unwrap(), vec![2]);
    }

    #[test]
    fn deposit_claim_space_matches_serialized_max() {
        let max = DepositClaim {
            txid: [u8::MAX; 32],
            vout: u32::MAX,
            amount: u64::MAX,
            recipient: Pubkey::new_unique(),
            epoch: u64::MAX,
            protocol_version: u8::MAX,
            slot_created: u64::MAX,
            bump: u8::MAX,
            reserved: [0u8; 16],
        };
        let serialized = max.try_to_vec().unwrap();
        assert_eq!(8 + serialized.len(), DepositClaim::SPACE);
        assert_eq!(DepositClaim::SPACE, 118);
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
