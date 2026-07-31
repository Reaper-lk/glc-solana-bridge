//! Validated withdrawal-executor configuration (Phase 6, ADR-0013).
//!
//! Same discipline as `glc::config` and `solana::config`: every
//! security-relevant value is validated at startup and has **no silent
//! default**. The process refuses to run on a misconfiguration rather than
//! guessing.

use solana_sdk::commitment_config::CommitmentLevel;
use thiserror::Error;

use super::address::AddressError;
use super::vault::{MultisigVault, VaultError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WithdrawalConfigError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} is not a valid regtest P2PKH address: {source}")]
    InvalidAddress {
        field: &'static str,
        source: AddressError,
    },
    #[error("fee_rate_per_kb must be greater than zero — there is no safe default (D4)")]
    ZeroFeeRate,
    #[error("vault redeem script is unusable: {0}")]
    InvalidVault(#[from] VaultError),
    #[error(
        "change_address must be the vault address itself ({vault}), got {configured} — change \
         returns to the vault and is verified against the vault script before signing"
    )]
    ChangeAddressNotVault { vault: String, configured: String },
    #[error("withdrawal_confirmation_depth must be at least 1 — there is no safe default (D7)")]
    ZeroConfirmationDepth,
    #[error("max_inputs_per_payout must be at least 1")]
    ZeroMaxInputs,
    #[error(
        "withdrawal discovery commitment must be `finalized` (owner decision D5): a payout may \
         never be built from a non-finalized burn; got {0:?}"
    )]
    NonFinalizedCommitment(String),
}

/// Raw, pre-validation input assembled from environment variables.
pub struct RawWithdrawalConfig {
    /// The vault's P2SH M-of-N redeem script, hex (ADR-0015). The address is
    /// re-derived from it and cross-checked against `vault_address`.
    pub vault_redeem_script_hex: String,
    /// The expected vault address. Checked against the address the redeem
    /// script actually derives — a mismatch is refused rather than resolved.
    pub vault_address: String,
    /// Where change returns to. May equal `vault_address`.
    pub change_address: String,
    /// Atomic units per 1000 bytes. No default (D4).
    pub fee_rate_per_kb: u64,
    /// Outputs below this are never created.
    pub dust_threshold_atomic: u64,
    /// Vault UTXOs need this many confirmations before being spendable.
    pub vault_min_confirmations: i64,
    /// Payout depth before `Completed`. No default (D7).
    pub confirmation_depth: i64,
    pub max_inputs_per_payout: usize,
    /// Reservations older than this, with no payout row yet, are reclaimed
    /// (D10 — configuration only).
    pub reservation_timeout_secs: i64,
    /// Must be exactly "finalized" (D5).
    pub discovery_commitment: String,
    pub poll_interval_ms: u64,
}

#[derive(Debug, Clone)]
pub struct WithdrawalConfig {
    /// The validated P2SH multisig vault (ADR-0015). Replaces the Phase 6
    /// single-key P2PKH vault (D2), which is deleted.
    pub vault: MultisigVault,
    pub vault_address: String,
    pub vault_hash160: [u8; 20],
    pub change_address: String,
    pub change_hash160: [u8; 20],
    pub fee_rate_per_kb: u64,
    pub dust_threshold_atomic: u64,
    pub vault_min_confirmations: i64,
    pub confirmation_depth: i64,
    pub max_inputs_per_payout: usize,
    pub reservation_timeout_secs: i64,
    pub discovery_commitment: CommitmentLevel,
    pub poll_interval_ms: u64,
}

impl WithdrawalConfig {
    pub fn validate(raw: RawWithdrawalConfig) -> Result<Self, WithdrawalConfigError> {
        if raw.vault_address.is_empty() {
            return Err(WithdrawalConfigError::Empty {
                field: "vault_address",
            });
        }
        if raw.change_address.is_empty() {
            return Err(WithdrawalConfigError::Empty {
                field: "change_address",
            });
        }
        // Derive the vault from its redeem script and refuse to proceed if
        // the configured address disagrees: a stale or transposed address
        // would otherwise send funds somewhere unrecoverable.
        let vault = MultisigVault::from_redeem_script_hex(&raw.vault_redeem_script_hex)?;
        vault.require_address(&raw.vault_address)?;
        let vault_hash160 = vault.script_hash160;
        // Change returns to the vault, and the builder verifies the change
        // output against the vault's own script before signing. Allowing a
        // different address here would make those two disagree, so the
        // relationship is enforced rather than assumed.
        if raw.change_address != vault.address {
            return Err(WithdrawalConfigError::ChangeAddressNotVault {
                vault: vault.address.clone(),
                configured: raw.change_address,
            });
        }
        let change_hash160 = vault.script_hash160;
        if raw.fee_rate_per_kb == 0 {
            return Err(WithdrawalConfigError::ZeroFeeRate);
        }
        if raw.confirmation_depth < 1 {
            return Err(WithdrawalConfigError::ZeroConfirmationDepth);
        }
        if raw.max_inputs_per_payout == 0 {
            return Err(WithdrawalConfigError::ZeroMaxInputs);
        }
        // D5: finalized is not merely the default, it is the only accepted
        // value. Building a payout from a reversible burn could pay out real
        // value against a burn that never happened.
        if raw.discovery_commitment != "finalized" {
            return Err(WithdrawalConfigError::NonFinalizedCommitment(
                raw.discovery_commitment,
            ));
        }

        Ok(WithdrawalConfig {
            vault,
            vault_address: raw.vault_address,
            vault_hash160,
            change_address: raw.change_address,
            change_hash160,
            fee_rate_per_kb: raw.fee_rate_per_kb,
            dust_threshold_atomic: raw.dust_threshold_atomic,
            vault_min_confirmations: raw.vault_min_confirmations,
            confirmation_depth: raw.confirmation_depth,
            max_inputs_per_payout: raw.max_inputs_per_payout,
            reservation_timeout_secs: raw.reservation_timeout_secs,
            discovery_commitment: CommitmentLevel::Finalized,
            poll_interval_ms: raw.poll_interval_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "mimgHRXobzhMFWkXH46awwtiAQLhKRxxbt";
    /// The real 2-of-3 vault produced by `createmultisig` on a regtest node
    /// during Phase 7b verification.
    const REDEEM: &str = "5221028e7147e643d67093dc8ca6a8fb888f1a452dddc62de991c7ed72080d65a421e42102f1c88ca7176c3ffee952ee6fae697991b257b6d53c3bc88e81cfe99adbcdbee5210256220bb7865197a40c4590ac80f12ef18e9063eac2eff92c4476ec27034042f953ae";
    const VAULT_ADDR: &str = "QY9YcpypWD91BEZ37TjNHYoqrquhcnVBYV";

    fn base() -> RawWithdrawalConfig {
        RawWithdrawalConfig {
            vault_redeem_script_hex: REDEEM.into(),
            vault_address: VAULT_ADDR.into(),
            change_address: VAULT_ADDR.into(),
            fee_rate_per_kb: 10_000,
            dust_threshold_atomic: 5_400,
            vault_min_confirmations: 1,
            confirmation_depth: 6,
            max_inputs_per_payout: 20,
            reservation_timeout_secs: 900,
            discovery_commitment: "finalized".into(),
            poll_interval_ms: 2_000,
        }
    }

    #[test]
    fn accepts_a_well_formed_config() {
        let c = WithdrawalConfig::validate(base()).unwrap();
        assert_eq!(c.discovery_commitment, CommitmentLevel::Finalized);
        assert_eq!(c.vault.threshold, 2);
        assert_eq!(c.vault.signer_count(), 3);
        assert_eq!(c.vault_address, VAULT_ADDR);
        assert_eq!(c.vault_hash160, c.vault.script_hash160);
    }

    #[test]
    fn refuses_a_vault_address_that_disagrees_with_its_redeem_script() {
        // A stale or transposed address would otherwise send vault funds
        // somewhere unrecoverable (ADR-0015).
        let mut r = base();
        r.vault_address = "QY9YcpypWD91BEZ37TjNHYoqrquhcnVBYW".into();
        assert!(matches!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::InvalidVault(_)
        ));
    }

    #[test]
    fn refuses_a_change_address_that_is_not_the_vault() {
        let mut r = base();
        r.change_address = ADDR.into(); // a P2PKH address, not the vault
        assert!(matches!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::ChangeAddressNotVault { .. }
        ));
    }

    #[test]
    fn refuses_a_malformed_redeem_script() {
        let mut r = base();
        r.vault_redeem_script_hex = "deadbeef".into();
        assert!(matches!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::InvalidVault(_)
        ));
    }

    #[test]
    fn rejects_zero_fee_rate_no_silent_default() {
        let mut r = base();
        r.fee_rate_per_kb = 0;
        assert_eq!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::ZeroFeeRate
        );
    }

    #[test]
    fn rejects_zero_confirmation_depth_no_silent_default() {
        let mut r = base();
        r.confirmation_depth = 0;
        assert_eq!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::ZeroConfirmationDepth
        );
    }

    #[test]
    fn rejects_every_commitment_except_finalized() {
        for level in ["processed", "confirmed", "", "Finalized", "FINALIZED"] {
            let mut r = base();
            r.discovery_commitment = level.into();
            assert!(
                matches!(
                    WithdrawalConfig::validate(r).unwrap_err(),
                    WithdrawalConfigError::NonFinalizedCommitment(_)
                ),
                "{level:?} must be rejected — D5 requires exactly `finalized`"
            );
        }
    }

    #[test]
    fn rejects_invalid_or_empty_addresses() {
        let mut r = base();
        r.vault_address = String::new();
        assert_eq!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::Empty {
                field: "vault_address"
            }
        );

        let mut r = base();
        r.change_address = "not-an-address".into();
        assert!(matches!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::ChangeAddressNotVault { .. }
        ));
    }

    #[test]
    fn rejects_zero_max_inputs() {
        let mut r = base();
        r.max_inputs_per_payout = 0;
        assert_eq!(
            WithdrawalConfig::validate(r).unwrap_err(),
            WithdrawalConfigError::ZeroMaxInputs
        );
    }
}
