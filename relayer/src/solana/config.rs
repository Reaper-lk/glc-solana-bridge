//! Validated Solana-side configuration (Phase 5, ADR-0012).
//!
//! Mirrors `glc::config`'s discipline: every value is validated strictly at
//! startup, with no silent defaults for security-relevant parameters
//! (owner decision R3 — the confirmation commitment level has no built-in
//! default and must be configured explicitly).

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
    #[error(
        "no validator keypair paths configured — at least one is required (owner decision R2)"
    )]
    NoValidatorKeypairs,
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
    /// One file per validator identity — see `signer` module's
    /// bootstrap-topology warning (owner decision R2).
    pub validator_keypair_paths: Vec<PathBuf>,
    /// No default (owner decision R3) — required.
    pub commitment: String,
    pub poll_interval_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SolanaConfig {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub submitter_keypair_path: PathBuf,
    pub validator_keypair_paths: Vec<PathBuf>,
    pub commitment: CommitmentLevel,
    pub poll_interval_ms: u64,
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
        if raw.validator_keypair_paths.is_empty() {
            return Err(SolanaConfigError::NoValidatorKeypairs);
        }
        let commitment = match raw.commitment.as_str() {
            "processed" => CommitmentLevel::Processed,
            "confirmed" => CommitmentLevel::Confirmed,
            "finalized" => CommitmentLevel::Finalized,
            other => return Err(SolanaConfigError::InvalidCommitment(other.to_string())),
        };

        Ok(SolanaConfig {
            rpc_url: raw.rpc_url,
            program_id,
            submitter_keypair_path: raw.submitter_keypair_path,
            validator_keypair_paths: raw.validator_keypair_paths,
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
            validator_keypair_paths: vec![PathBuf::from("/tmp/v1.json")],
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
    fn rejects_no_validator_keypairs() {
        let mut raw = base_raw();
        raw.validator_keypair_paths = vec![];
        assert_eq!(
            SolanaConfig::validate(raw).unwrap_err(),
            SolanaConfigError::NoValidatorKeypairs
        );
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
