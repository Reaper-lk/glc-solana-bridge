//! Canonical federation-signed governance messages (Phase 7a, ADR-0014).
//!
//! Governance actions are authorized by exactly the same M-of-N mechanism as
//! deposit mints (ADR-0010): an ed25519-precompile instruction immediately
//! before the governance instruction, carrying threshold signatures over the
//! canonical bytes built here. No second authorization mechanism exists.
//!
//! # Why the parameters are hashed rather than inlined
//!
//! A rotation's parameters (up to 16 pubkeys) are far too large to embed in
//! the signed message. Every signature entry in the precompile payload costs
//! 110 bytes and the message is stored once, so inlining a 517-byte
//! parameter blob would push a 4-signature rotation past the 1232-byte
//! legacy transaction limit on its own — before the instruction's own copy
//! of the same list is counted (ADR-0010 measured the same ceiling for
//! mints).
//!
//! Instead the message commits to `sha256(canonical parameter bytes)`, which
//! keeps it a fixed [`GOVERNANCE_MESSAGE_LEN`] bytes regardless of validator
//! count. The program recomputes that hash from the instruction arguments
//! and compares, so a signature still authorizes exactly one parameter set —
//! the binding is identical in strength, only the encoding is compact.
//!
//! This crate stays dependency-free (see Cargo.toml's hard rules), so the
//! hashing itself is performed by the caller: on-chain via
//! `solana_program::hash`, off-chain via `sha2`. Both are SHA-256 over the
//! bytes laid out by [`rotation_params`], which is the single source of
//! truth for that layout.

/// 16-byte domain tag, distinct from `claim::CLAIM_DOMAIN_TAG`. A governance
/// signature can therefore never be reinterpreted as a deposit claim, or
/// vice versa, even if every other field coincided.
pub const GOVERNANCE_DOMAIN_TAG: &[u8; 16] = b"GLC_BRIDGE_GOVRN";

/// Propose a validator-set/threshold rotation. Continues the action-type
/// numbering started by `claim::ACTION_MINT_DEPOSIT` (0x01); 0x00 remains
/// permanently invalid.
pub const ACTION_PROPOSE_ROTATION: u8 = 0x03;

/// Cancel the currently pending governance action.
pub const ACTION_CANCEL_ROTATION: u8 = 0x04;

/// Exact length of a governance message: 16 + 1 + 32 + 8 + 1 + 32.
pub const GOVERNANCE_MESSAGE_LEN: usize = 90;

/// Builds the canonical governance message.
///
/// Layout (all integers little-endian):
///
/// | offset | len | field |
/// |--------|-----|-------|
/// | 0      | 16  | domain tag `b"GLC_BRIDGE_GOVRN"` |
/// | 16     | 1   | protocol version |
/// | 17     | 32  | Solana program id |
/// | 49     | 8   | current validator-set epoch (`u64` LE) |
/// | 57     | 1   | action type |
/// | 58     | 32  | parameter commitment (SHA-256) |
///
/// Binding the **current** epoch means a governance signature dies the
/// moment the federation rotates — the same property ADR-0010 gives deposit
/// claims. Binding the program id prevents a signature collected for one
/// deployment being replayed against another.
///
/// Pure and allocation-free, so it is byte-identical under SBF and on the
/// host (the same discipline as `claim::deposit_claim_message`).
pub fn governance_message(
    protocol_version: u8,
    program_id: &[u8; 32],
    epoch: u64,
    action: u8,
    params_commitment: &[u8; 32],
) -> [u8; GOVERNANCE_MESSAGE_LEN] {
    let mut m = [0u8; GOVERNANCE_MESSAGE_LEN];
    m[0..16].copy_from_slice(GOVERNANCE_DOMAIN_TAG);
    m[16] = protocol_version;
    m[17..49].copy_from_slice(program_id);
    m[49..57].copy_from_slice(&epoch.to_le_bytes());
    m[57] = action;
    m[58..90].copy_from_slice(params_commitment);
    m
}

/// Canonical byte layout of a rotation's parameters, which the caller hashes
/// to obtain the `params_commitment` for [`governance_message`].
///
/// Layout: `threshold (1) ‖ validator_count (4 LE) ‖ validators (32 each,
/// in the order proposed)`.
///
/// Validator **order is significant**: it is the order the set will be
/// stored in, and it determines each validator's bitmask index in the
/// on-chain duplicate check. Two proposals differing only in ordering are
/// genuinely different proposals and produce different commitments.
pub fn rotation_params(threshold: u8, validators: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + validators.len() * 32);
    out.push(threshold);
    out.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        out.extend_from_slice(v);
    }
    out
}

/// Canonical parameter layout for a cancellation.
///
/// A cancel signature must not be replayable against a *different* pending
/// action, so it commits to the exact action it cancels: the pending
/// action's type and its execution time.
pub fn cancel_params(pending_action: u8, pending_eta: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8);
    out.push(pending_action);
    out.extend_from_slice(&pending_eta.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector: pins every byte of the encoding. A change here breaks
    /// every outstanding governance signature and must be deliberate.
    #[test]
    fn governance_message_golden_vector() {
        let m = governance_message(
            1,
            &[0x11; 32],
            0x0102030405060708,
            ACTION_PROPOSE_ROTATION,
            &[0x22; 32],
        );
        let mut expected = Vec::with_capacity(GOVERNANCE_MESSAGE_LEN);
        expected.extend_from_slice(b"GLC_BRIDGE_GOVRN");
        expected.push(1);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // LE
        expected.push(0x03);
        expected.extend_from_slice(&[0x22; 32]);
        assert_eq!(expected.len(), GOVERNANCE_MESSAGE_LEN);
        assert_eq!(m.as_slice(), expected.as_slice());
    }

    #[test]
    fn domain_tag_is_distinct_from_the_claim_tag() {
        assert_ne!(
            GOVERNANCE_DOMAIN_TAG.as_slice(),
            crate::claim::CLAIM_DOMAIN_TAG.as_slice(),
            "a governance signature must never be reinterpretable as a claim"
        );
        assert_eq!(GOVERNANCE_DOMAIN_TAG.len(), 16);
    }

    #[test]
    fn action_types_do_not_collide_with_the_claim_action() {
        assert_ne!(ACTION_PROPOSE_ROTATION, crate::claim::ACTION_MINT_DEPOSIT);
        assert_ne!(ACTION_CANCEL_ROTATION, crate::claim::ACTION_MINT_DEPOSIT);
        assert_ne!(ACTION_PROPOSE_ROTATION, ACTION_CANCEL_ROTATION);
        assert_ne!(
            ACTION_PROPOSE_ROTATION, 0x00,
            "0x00 is never a valid action"
        );
    }

    #[test]
    fn every_field_changes_the_message() {
        let base = governance_message(1, &[0x11; 32], 7, ACTION_PROPOSE_ROTATION, &[0x22; 32]);
        assert_ne!(
            base,
            governance_message(2, &[0x11; 32], 7, ACTION_PROPOSE_ROTATION, &[0x22; 32])
        );
        assert_ne!(
            base,
            governance_message(1, &[0x99; 32], 7, ACTION_PROPOSE_ROTATION, &[0x22; 32])
        );
        assert_ne!(
            base,
            governance_message(1, &[0x11; 32], 8, ACTION_PROPOSE_ROTATION, &[0x22; 32])
        );
        assert_ne!(
            base,
            governance_message(1, &[0x11; 32], 7, ACTION_CANCEL_ROTATION, &[0x22; 32])
        );
        assert_ne!(
            base,
            governance_message(1, &[0x11; 32], 7, ACTION_PROPOSE_ROTATION, &[0x33; 32])
        );
    }

    #[test]
    fn rotation_params_layout_is_pinned() {
        let v = [[0xAAu8; 32], [0xBBu8; 32]];
        let p = rotation_params(3, &v);
        assert_eq!(p.len(), 1 + 4 + 64);
        assert_eq!(p[0], 3);
        assert_eq!(&p[1..5], &2u32.to_le_bytes());
        assert_eq!(&p[5..37], &[0xAA; 32]);
        assert_eq!(&p[37..69], &[0xBB; 32]);
    }

    #[test]
    fn rotation_params_distinguish_order_threshold_and_membership() {
        let a = [[0xAAu8; 32], [0xBBu8; 32]];
        let reordered = [[0xBBu8; 32], [0xAAu8; 32]];
        let different = [[0xAAu8; 32], [0xCCu8; 32]];
        assert_ne!(rotation_params(2, &a), rotation_params(2, &reordered));
        assert_ne!(rotation_params(2, &a), rotation_params(1, &a));
        assert_ne!(rotation_params(2, &a), rotation_params(2, &different));
        // A shorter set must not be a prefix-collision of a longer one.
        assert_ne!(rotation_params(2, &a), rotation_params(2, &a[..1]));
    }

    #[test]
    fn cancel_params_bind_the_specific_pending_action() {
        assert_eq!(cancel_params(ACTION_PROPOSE_ROTATION, 1_000).len(), 9);
        assert_ne!(
            cancel_params(ACTION_PROPOSE_ROTATION, 1_000),
            cancel_params(ACTION_PROPOSE_ROTATION, 1_001),
            "a cancel signature must not be replayable against a re-proposal"
        );
    }

    #[test]
    fn message_length_matches_the_constant() {
        assert_eq!(
            governance_message(1, &[0; 32], 0, ACTION_PROPOSE_ROTATION, &[0; 32]).len(),
            GOVERNANCE_MESSAGE_LEN
        );
    }
}
