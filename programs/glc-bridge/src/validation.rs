//! Pure validation rules for the federation validator set, shared by
//! `initialize` and `update_validator_set` so the two paths can never drift.
//! Kept free of account types so the rules are unit-testable without a
//! runtime.

use anchor_lang::prelude::*;

use crate::constants::MAX_VALIDATORS;
use crate::errors::BridgeError;

/// Enforces every invariant of a (validators, threshold) pair:
/// non-empty, `len <= MAX_VALIDATORS`, no all-zero (default) keys, no
/// duplicate keys, `1 <= threshold <= len`.
pub fn validate_validator_set(validators: &[Pubkey], threshold: u8) -> Result<()> {
    require!(!validators.is_empty(), BridgeError::EmptyValidatorSet);
    require!(
        validators.len() <= MAX_VALIDATORS,
        BridgeError::TooManyValidators
    );
    require!(threshold >= 1, BridgeError::ZeroThreshold);
    require!(
        usize::from(threshold) <= validators.len(),
        BridgeError::ThresholdExceedsValidatorCount
    );
    // The all-zero pubkey has no usable signing key; counting it toward N
    // could make the threshold unreachable and stall the bridge.
    for validator in validators {
        require!(
            *validator != Pubkey::default(),
            BridgeError::InvalidValidatorKey
        );
    }
    // O(n²) pairwise scan: n <= 16, so at most 120 comparisons — cheaper and
    // simpler than sorting or hashing on-chain.
    for i in 0..validators.len() {
        for j in (i + 1)..validators.len() {
            require!(
                validators[i] != validators[j],
                BridgeError::DuplicateValidator
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<Pubkey> {
        (0..n).map(|_| Pubkey::new_unique()).collect()
    }

    fn err_of(validators: &[Pubkey], threshold: u8) -> Error {
        validate_validator_set(validators, threshold).unwrap_err()
    }

    #[test]
    fn accepts_minimal_set_1_of_1() {
        assert!(validate_validator_set(&keys(1), 1).is_ok());
    }

    #[test]
    fn accepts_full_set_16_of_16() {
        assert!(validate_validator_set(&keys(MAX_VALIDATORS), MAX_VALIDATORS as u8).is_ok());
    }

    #[test]
    fn accepts_partial_threshold() {
        assert!(validate_validator_set(&keys(5), 3).is_ok());
    }

    #[test]
    fn rejects_empty_set() {
        assert_eq!(err_of(&[], 1), Error::from(BridgeError::EmptyValidatorSet));
    }

    #[test]
    fn rejects_seventeen_validators() {
        assert_eq!(
            err_of(&keys(MAX_VALIDATORS + 1), 1),
            Error::from(BridgeError::TooManyValidators)
        );
    }

    #[test]
    fn rejects_zero_threshold() {
        assert_eq!(err_of(&keys(3), 0), Error::from(BridgeError::ZeroThreshold));
    }

    #[test]
    fn rejects_threshold_above_count() {
        assert_eq!(
            err_of(&keys(3), 4),
            Error::from(BridgeError::ThresholdExceedsValidatorCount)
        );
    }

    #[test]
    fn rejects_all_zero_validator_key() {
        let mut v = keys(3);
        v[1] = Pubkey::default();
        assert_eq!(err_of(&v, 2), Error::from(BridgeError::InvalidValidatorKey));
    }

    #[test]
    fn rejects_adjacent_duplicate() {
        let mut v = keys(3);
        v[1] = v[0];
        assert_eq!(err_of(&v, 1), Error::from(BridgeError::DuplicateValidator));
    }

    #[test]
    fn rejects_non_adjacent_duplicate() {
        let mut v = keys(MAX_VALIDATORS);
        v[MAX_VALIDATORS - 1] = v[0];
        assert_eq!(err_of(&v, 1), Error::from(BridgeError::DuplicateValidator));
    }

    #[test]
    fn empty_set_reported_before_threshold() {
        // Ordering matters for stable client-side error handling.
        assert_eq!(err_of(&[], 0), Error::from(BridgeError::EmptyValidatorSet));
    }
}
