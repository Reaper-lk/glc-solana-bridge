//! Strict parser for the ed25519-precompile instruction that carries the
//! federation's signatures (ADR-0010).
//!
//! Trust model: the runtime's ed25519 precompile has ALREADY verified every
//! signature in the instruction before this program executes — an invalid
//! signature aborts the whole transaction. What the precompile does NOT
//! guarantee is *what* was signed by *whom relevant to us*; that is this
//! module's job, and it is deliberately paranoid:
//!
//! - every offset is bounds-checked with checked arithmetic;
//! - every entry must be fully self-referential (`u16::MAX` instruction
//!   indices) — entries may never point into other instructions' data,
//!   closing the classic introspection confusion attacks;
//! - every entry's message must be byte-identical to the expected canonical
//!   claim message;
//! - signers must be current validators, and duplicates are hard errors.
//!
//! Kept free of account types so the whole parser is unit-testable against
//! fabricated (including malformed) instruction bytes.

use anchor_lang::prelude::*;

use crate::constants::MAX_VALIDATORS;
use crate::errors::BridgeError;

/// `num_signatures: u8` + `padding: u8`.
const ED25519_HEADER_LEN: usize = 2;
/// Seven `u16` fields per signature entry.
const ED25519_ENTRY_LEN: usize = 14;
const SIGNATURE_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;
/// "This instruction" sentinel for the precompile's instruction indices.
const SELF_REFERENCE: u16 = u16::MAX;

// The dedup bitmask below is a u16; a larger validator cap would overflow it.
const _: () = assert!(MAX_VALIDATORS <= 16);

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(BridgeError::MalformedSignatureVerification)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Parses the ed25519 instruction's data and returns the number of UNIQUE
/// current validators that signed `expected_message`.
///
/// Errors rather than skips on anything unexpected: malformed layout,
/// out-of-bounds offsets, cross-instruction references, a message that is
/// not byte-identical to `expected_message`, a signer that is not a current
/// validator, or the same validator appearing twice.
pub fn count_unique_validator_signers(
    data: &[u8],
    expected_message: &[u8],
    validators: &[Pubkey],
) -> Result<usize> {
    require!(
        data.len() >= ED25519_HEADER_LEN,
        BridgeError::MalformedSignatureVerification
    );
    let num_signatures = data[0] as usize;
    require!(
        num_signatures >= 1 && data[1] == 0,
        BridgeError::MalformedSignatureVerification
    );

    let mut seen: u16 = 0;
    let mut count: usize = 0;

    for i in 0..num_signatures {
        let entry_base = ED25519_HEADER_LEN
            .checked_add(
                i.checked_mul(ED25519_ENTRY_LEN)
                    .ok_or(BridgeError::MalformedSignatureVerification)?,
            )
            .ok_or(BridgeError::MalformedSignatureVerification)?;

        let signature_offset = u16_at(data, entry_base)? as usize;
        let signature_ix_index = u16_at(data, entry_base + 2)?;
        let public_key_offset = u16_at(data, entry_base + 4)? as usize;
        let public_key_ix_index = u16_at(data, entry_base + 6)?;
        let message_offset = u16_at(data, entry_base + 8)? as usize;
        let message_size = u16_at(data, entry_base + 10)? as usize;
        let message_ix_index = u16_at(data, entry_base + 12)?;

        // All references must point into THIS instruction's own data.
        require!(
            signature_ix_index == SELF_REFERENCE
                && public_key_ix_index == SELF_REFERENCE
                && message_ix_index == SELF_REFERENCE,
            BridgeError::MalformedSignatureVerification
        );

        // The signature bytes must exist in-bounds (their validity was
        // proven by the precompile).
        let sig_end = signature_offset
            .checked_add(SIGNATURE_LEN)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        require!(
            data.get(signature_offset..sig_end).is_some(),
            BridgeError::MalformedSignatureVerification
        );

        // The signed message must be exactly the expected claim bytes.
        let msg_end = message_offset
            .checked_add(message_size)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        let message = data
            .get(message_offset..msg_end)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        require!(
            message == expected_message,
            BridgeError::SignatureMessageMismatch
        );

        // The signer must be a current validator...
        let pk_end = public_key_offset
            .checked_add(PUBKEY_LEN)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        let pk_bytes = data
            .get(public_key_offset..pk_end)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        let signer =
            Pubkey::try_from(pk_bytes).map_err(|_| BridgeError::MalformedSignatureVerification)?;
        let validator_index = validators
            .iter()
            .position(|v| *v == signer)
            .ok_or(BridgeError::UnknownValidatorSignature)?;

        // ...and must not have been counted already.
        let bit = 1u16
            .checked_shl(validator_index as u32)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
        require!(seen & bit == 0, BridgeError::DuplicateValidatorSignature);
        seen |= bit;
        count = count
            .checked_add(1)
            .ok_or(BridgeError::MalformedSignatureVerification)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"canonical message bytes for unit tests only....";

    fn validators(n: usize) -> Vec<Pubkey> {
        (0..n).map(|_| Pubkey::new_unique()).collect()
    }

    /// Builds well-formed ed25519 instruction data: entries first, then per
    /// entry pubkey + signature, then one shared message.
    fn build(entries: &[Pubkey], message: &[u8]) -> Vec<u8> {
        let n = entries.len();
        let entries_end = ED25519_HEADER_LEN + n * ED25519_ENTRY_LEN;
        let keys_end = entries_end + n * PUBKEY_LEN;
        let sigs_end = keys_end + n * SIGNATURE_LEN;
        let msg_offset = sigs_end;

        let mut data = vec![0u8; msg_offset + message.len()];
        data[0] = n as u8;
        data[1] = 0;
        for (i, pk) in entries.iter().enumerate() {
            let base = ED25519_HEADER_LEN + i * ED25519_ENTRY_LEN;
            let sig_off = (keys_end + i * SIGNATURE_LEN) as u16;
            let pk_off = (entries_end + i * PUBKEY_LEN) as u16;
            data[base..base + 2].copy_from_slice(&sig_off.to_le_bytes());
            data[base + 2..base + 4].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
            data[base + 4..base + 6].copy_from_slice(&pk_off.to_le_bytes());
            data[base + 6..base + 8].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
            data[base + 8..base + 10].copy_from_slice(&(msg_offset as u16).to_le_bytes());
            data[base + 10..base + 12].copy_from_slice(&(message.len() as u16).to_le_bytes());
            data[base + 12..base + 14].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
            let pk_pos = entries_end + i * PUBKEY_LEN;
            data[pk_pos..pk_pos + PUBKEY_LEN].copy_from_slice(pk.as_ref());
            // signature bytes stay zeroed — validity is the precompile's
            // concern, not the parser's.
        }
        data[msg_offset..].copy_from_slice(message);
        data
    }

    fn err_of(data: &[u8], validators: &[Pubkey]) -> Error {
        count_unique_validator_signers(data, MSG, validators).unwrap_err()
    }

    #[test]
    fn counts_all_unique_valid_signers() {
        let v = validators(5);
        let data = build(&[v[0], v[2], v[4]], MSG);
        assert_eq!(count_unique_validator_signers(&data, MSG, &v).unwrap(), 3);
    }

    #[test]
    fn full_sixteen_validator_set_counts() {
        let v = validators(16);
        let data = build(&v, MSG);
        assert_eq!(count_unique_validator_signers(&data, MSG, &v).unwrap(), 16);
    }

    #[test]
    fn rejects_duplicate_signer() {
        let v = validators(3);
        let data = build(&[v[0], v[1], v[0]], MSG);
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::DuplicateValidatorSignature)
        );
    }

    #[test]
    fn rejects_unknown_signer() {
        let v = validators(3);
        let outsider = Pubkey::new_unique();
        let data = build(&[v[0], outsider], MSG);
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::UnknownValidatorSignature)
        );
    }

    #[test]
    fn rejects_wrong_message() {
        let v = validators(3);
        let data = build(&[v[0], v[1]], b"some other message entirely.....");
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::SignatureMessageMismatch)
        );
    }

    #[test]
    fn rejects_message_with_matching_prefix_but_wrong_length() {
        let v = validators(3);
        let mut long = MSG.to_vec();
        long.push(0);
        let data = build(&[v[0]], &long);
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::SignatureMessageMismatch)
        );
    }

    #[test]
    fn rejects_cross_instruction_reference() {
        let v = validators(3);
        let mut data = build(&[v[0]], MSG);
        // message_instruction_index := 0 (another instruction).
        let base = ED25519_HEADER_LEN;
        data[base + 12..base + 14].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }

    #[test]
    fn rejects_zero_signature_count() {
        let v = validators(3);
        let mut data = build(&[v[0]], MSG);
        data[0] = 0;
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }

    #[test]
    fn rejects_nonzero_padding() {
        let v = validators(3);
        let mut data = build(&[v[0]], MSG);
        data[1] = 1;
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }

    #[test]
    fn rejects_truncated_data() {
        let v = validators(3);
        let data = build(&[v[0], v[1]], MSG);
        // Claim 2 signatures but cut the buffer inside the second entry.
        let truncated = &data[..ED25519_HEADER_LEN + ED25519_ENTRY_LEN + 4];
        assert_eq!(
            err_of(truncated, &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }

    #[test]
    fn rejects_out_of_bounds_message_offset() {
        let v = validators(3);
        let mut data = build(&[v[0]], MSG);
        let base = ED25519_HEADER_LEN;
        data[base + 8..base + 10].copy_from_slice(&u16::MAX.to_le_bytes()[..2]);
        // message_instruction_index stays SELF_REFERENCE; offset now absurd.
        data[base + 12..base + 14].copy_from_slice(&SELF_REFERENCE.to_le_bytes());
        assert_eq!(
            err_of(&data, &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }

    #[test]
    fn rejects_empty_data() {
        let v = validators(1);
        assert_eq!(
            err_of(&[], &v),
            Error::from(BridgeError::MalformedSignatureVerification)
        );
    }
}
