//! Validated Solana-side configuration (Phase 5, ADR-0012).
//!
//! Mirrors `glc::config`'s discipline: every value is validated strictly at
//! startup, with no silent defaults for security-relevant parameters
//! (owner decision R3 — the confirmation commitment level has no built-in
//! default and must be configured explicitly).
//!
//! # No validator keypair paths here (Phase 7d)
//!
//! `validator_keypair_paths` is **removed**. The relayer holds no validator
//! key, so requiring it to be configured with paths to them was worse than
//! redundant: it invited operators to place federation key material in the
//! relayer's environment, which is exactly the topology Phase 7c retired.
//! A validator key is configured only for `signer-server`, in its own
//! process, via `GLC_SIGNER_VALIDATOR_KEYPAIR_PATH` (singular).

use std::path::PathBuf;

use solana_sdk::commitment_config::CommitmentLevel;
use solana_sdk::pubkey::Pubkey;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SolanaConfigError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must be a valid base58 Solana pubkey: {reason}")]
    InvalidPubkey { field: &'static str, reason: String },
    #[error("commitment level must be one of processed|confirmed|finalized, got {0:?}")]
    InvalidCommitment(String),
}

/// Raw, pre-validation input — assembled from environment variables by the
/// binary's entrypoint.
pub struct RawSolanaConfig {
    pub rpc_url: String,
    pub program_id: String,
    /// Pays every mint_wrapped transaction's fees (owner decision R4).
    pub submitter_keypair_path: PathBuf,
    /// No default (owner decision R3) — required.
    pub commitment: String,
    pub poll_interval_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SolanaConfig {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub submitter_keypair_path: PathBuf,
    pub commitment: CommitmentLevel,
    pub poll_interval_ms: u64,
}

/// Parses a commitment level. There is deliberately no default: the level a
/// deployment confirms at is a security decision (owner decision R3).
///
/// Shared by [`SolanaConfig::validate`] and `signer-server`, so the two
/// processes cannot come to disagree about what `finalized` means.
pub fn parse_commitment(s: &str) -> Result<CommitmentLevel, SolanaConfigError> {
    match s {
        "processed" => Ok(CommitmentLevel::Processed),
        "confirmed" => Ok(CommitmentLevel::Confirmed),
        "finalized" => Ok(CommitmentLevel::Finalized),
        other => Err(SolanaConfigError::InvalidCommitment(other.to_string())),
    }
}

impl SolanaConfig {
    pub fn validate(raw: RawSolanaConfig) -> Result<Self, SolanaConfigError> {
        if raw.rpc_url.is_empty() {
            return Err(SolanaConfigError::Empty { field: "rpc_url" });
        }
        let program_id: Pubkey =
            raw.program_id
                .parse()
                .map_err(|e: solana_sdk::pubkey::ParsePubkeyError| {
                    SolanaConfigError::InvalidPubkey {
                        field: "program_id",
                        reason: e.to_string(),
                    }
                })?;
        let commitment = parse_commitment(&raw.commitment)?;

        Ok(SolanaConfig {
            rpc_url: raw.rpc_url,
            program_id,
            submitter_keypair_path: raw.submitter_keypair_path,
            commitment,
            poll_interval_ms: raw.poll_interval_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_raw() -> RawSolanaConfig {
        RawSolanaConfig {
            rpc_url: "http://127.0.0.1:8899".into(),
            program_id: Pubkey::new_unique().to_string(),
            submitter_keypair_path: PathBuf::from("/tmp/submitter.json"),
            commitment: "confirmed".into(),
            poll_interval_ms: 1000,
        }
    }

    #[test]
    fn accepts_well_formed_config() {
        let cfg = SolanaConfig::validate(base_raw()).unwrap();
        assert_eq!(cfg.commitment, CommitmentLevel::Confirmed);
    }

    #[test]
    fn rejects_empty_rpc_url() {
        let mut raw = base_raw();
        raw.rpc_url = String::new();
        assert_eq!(
            SolanaConfig::validate(raw).unwrap_err(),
            SolanaConfigError::Empty { field: "rpc_url" }
        );
    }

    #[test]
    fn rejects_invalid_program_id() {
        let mut raw = base_raw();
        raw.program_id = "not-a-pubkey".into();
        assert!(matches!(
            SolanaConfig::validate(raw).unwrap_err(),
            SolanaConfigError::InvalidPubkey {
                field: "program_id",
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_commitment_default() {
        let mut raw = base_raw();
        raw.commitment = String::new();
        assert_eq!(
            SolanaConfig::validate(raw).unwrap_err(),
            SolanaConfigError::InvalidCommitment(String::new())
        );
    }

    #[test]
    fn rejects_unknown_commitment_string() {
        let mut raw = base_raw();
        raw.commitment = "eventually".into();
        assert_eq!(
            SolanaConfig::validate(raw).unwrap_err(),
            SolanaConfigError::InvalidCommitment("eventually".into())
        );
    }

    #[test]
    fn accepts_all_three_commitment_levels() {
        for (s, expected) in [
            ("processed", CommitmentLevel::Processed),
            ("confirmed", CommitmentLevel::Confirmed),
            ("finalized", CommitmentLevel::Finalized),
        ] {
            let mut raw = base_raw();
            raw.commitment = s.into();
            assert_eq!(SolanaConfig::validate(raw).unwrap().commitment, expected);
        }
    }
}
