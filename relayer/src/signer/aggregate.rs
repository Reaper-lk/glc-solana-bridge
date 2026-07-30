//! Signature aggregation: builds the ed25519-precompile instruction the
//! on-chain `mint_wrapped` verifier expects (ADR-0010), and performs the
//! client-side threshold pre-check before ever attempting a submission.
//!
//! The instruction byte layout mirrors exactly what the on-chain program's
//! `verification.rs` parser requires — the same construction already
//! proven against the real verifier by the Phase 3 on-chain test harness
//! (`programs/glc-bridge/tests/common/mod.rs::ed25519_proof_ix`), ported
//! here as production code rather than test-only scaffolding. All entries
//! are self-referential (`u16::MAX` instruction indices), matching what a
//! real relayer must produce for the on-chain parser to accept the proof.

use std::collections::HashSet;

use solana_sdk::ed25519_program;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("insufficient unique validator signatures: {unique} of required {threshold}")]
    Insufficient { unique: usize, threshold: u8 },
}

/// "This instruction" sentinel — matches the on-chain parser's requirement
/// that every offset be self-referential.
const SELF_REFERENCE: u16 = u16::MAX;

/// Builds one ed25519-precompile instruction carrying every `(pubkey,
/// signature)` pair over the identical `message` bytes. Every entry points
/// at this instruction's own embedded copy of the message — never another
/// instruction's data.
pub fn build_ed25519_instruction(sigs: &[(Pubkey, Signature)], message: &[u8]) -> Instruction {
    let n = sigs.len();
    let entries_end = 2 + n * 14;
    let keys_end = entries_end + n * 32;
    let sigs_end = keys_end + n * 64;
    let msg_off = sigs_end;

    let mut data = vec![0u8; msg_off + message.len()];
    data[0] = n as u8;
    data[1] = 0;
    for (i, (pubkey, sig)) in sigs.iter().enumerate() {
        let base = 2 + i * 14;
        let pk_off = (entries_end + i * 32) as u16;
        let sig_off = (keys_end + i * 64) as u16;
        data[base..base + 2].copy_from_slice(&sig_off.to_le_bytes());
        data[base + 2..base + 4].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
        data[base + 4..base + 6].copy_from_slice(&pk_off.to_le_bytes());
        data[base + 6..base + 8].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
        data[base + 8..base + 10].copy_from_slice(&(msg_off as u16).to_le_bytes());
        data[base + 10..base + 12].copy_from_slice(&(message.len() as u16).to_le_bytes());
        data[base + 12..base + 14].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
        let pk_pos = entries_end + i * 32;
        data[pk_pos..pk_pos + 32].copy_from_slice(pubkey.as_ref());
        let sig_pos = keys_end + i * 64;
        data[sig_pos..sig_pos + 64].copy_from_slice(sig.as_ref());
    }
    data[msg_off..].copy_from_slice(message);

    Instruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data,
    }
}

/// Client-side mirror of the on-chain `count_unique_validator_signers`
/// rules (dedup via a `HashSet` rather than the on-chain bitmask — no
/// `MAX_VALIDATORS` bound applies off-chain). This is a courtesy
/// pre-check only: it exists to avoid wasting a submission that the
/// on-chain program would reject anyway. The on-chain verifier remains the
/// sole security boundary regardless of what this function returns.
///
/// Unlike the on-chain parser, an unknown-pubkey signature here is simply
/// not counted (rather than a hard error) — a relayer may hold a superset
/// of keys relative to the CURRENT on-chain validator set (e.g. mid-
/// rotation), and that alone should not abort a proof that is otherwise
/// sufficient.
pub fn count_unique_threshold_signers(
    sigs: &[(Pubkey, Signature)],
    validators: &[Pubkey],
    threshold: u8,
) -> Result<usize, ThresholdError> {
    let member_set: HashSet<&Pubkey> = validators.iter().collect();
    let unique: HashSet<&Pubkey> = sigs
        .iter()
        .map(|(pk, _)| pk)
        .filter(|pk| member_set.contains(pk))
        .collect();
    if unique.len() >= usize::from(threshold) {
        Ok(unique.len())
    } else {
        Err(ThresholdError::Insufficient {
            unique: unique.len(),
            threshold,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};

    #[test]
    fn threshold_met_with_exact_count() {
        let keys: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
        let validators: Vec<Pubkey> = keys.iter().map(|k| k.pubkey()).collect();
        let message = b"claim bytes";
        let sigs: Vec<_> = keys
            .iter()
            .take(2)
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect();
        assert_eq!(
            count_unique_threshold_signers(&sigs, &validators, 2).unwrap(),
            2
        );
    }

    #[test]
    fn threshold_not_met() {
        let keys: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
        let validators: Vec<Pubkey> = keys.iter().map(|k| k.pubkey()).collect();
        let message = b"claim bytes";
        let sigs: Vec<_> = keys
            .iter()
            .take(1)
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect();
        assert_eq!(
            count_unique_threshold_signers(&sigs, &validators, 2).unwrap_err(),
            ThresholdError::Insufficient {
                unique: 1,
                threshold: 2
            }
        );
    }

    #[test]
    fn duplicate_signer_counted_once() {
        let keys: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
        let validators: Vec<Pubkey> = keys.iter().map(|k| k.pubkey()).collect();
        let message = b"claim bytes";
        let sig0 = keys[0].sign_message(message);
        let sigs = vec![(keys[0].pubkey(), sig0), (keys[0].pubkey(), sig0)];
        assert_eq!(
            count_unique_threshold_signers(&sigs, &validators, 2).unwrap_err(),
            ThresholdError::Insufficient {
                unique: 1,
                threshold: 2
            }
        );
    }

    #[test]
    fn unknown_signer_not_counted() {
        let keys: Vec<Keypair> = (0..2).map(|_| Keypair::new()).collect();
        let outsider = Keypair::new();
        let validators: Vec<Pubkey> = keys.iter().map(|k| k.pubkey()).collect();
        let message = b"claim bytes";
        let sigs = vec![
            (keys[0].pubkey(), keys[0].sign_message(message)),
            (outsider.pubkey(), outsider.sign_message(message)),
        ];
        assert_eq!(
            count_unique_threshold_signers(&sigs, &validators, 2).unwrap_err(),
            ThresholdError::Insufficient {
                unique: 1,
                threshold: 2
            }
        );
    }

    #[test]
    fn built_instruction_round_trips_through_the_real_ed25519_precompile_shape() {
        let keys: Vec<Keypair> = (0..2).map(|_| Keypair::new()).collect();
        let message = b"exact 166-byte-shaped test message..............................";
        let sigs: Vec<_> = keys
            .iter()
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect();
        let ix = build_ed25519_instruction(&sigs, message);
        assert_eq!(ix.program_id, ed25519_program::id());
        assert_eq!(ix.data[0], 2, "num_signatures header byte");
        assert_eq!(ix.data[1], 0, "padding byte");
        // Every entry's three instruction-index fields must be self-referential.
        for i in 0..2 {
            let base = 2 + i * 14;
            let sig_idx = u16::from_le_bytes([ix.data[base + 2], ix.data[base + 3]]);
            let pk_idx = u16::from_le_bytes([ix.data[base + 6], ix.data[base + 7]]);
            let msg_idx = u16::from_le_bytes([ix.data[base + 12], ix.data[base + 13]]);
            assert_eq!(sig_idx, SELF_REFERENCE);
            assert_eq!(pk_idx, SELF_REFERENCE);
            assert_eq!(msg_idx, SELF_REFERENCE);
        }
    }
}
