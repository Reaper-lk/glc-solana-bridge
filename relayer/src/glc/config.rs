//! Indexer configuration (ADR-0011).
//!
//! Every Solana-side fact the indexer needs (`protocol_version`, `program_id`,
//! `validator_epoch`, `wrapped_mint`) is explicit operator configuration in
//! Phase 4 (owner decision U4) — no Solana RPC exists in this workspace yet.
//! A stale value here fails safely: the on-chain program rejects a
//! stale-epoch or wrong-program-id proof (Phase 3, ADR-0010); it never mints
//! wrongly. Keeping this config in sync with live Solana state after a
//! validator-set rotation or redeployment is an operator responsibility
//! until Phase 5 automates it.
//!
//! No production defaults are supplied for `confirmation_depth` or
//! `max_reorg_depth` (owner decision U6): Goldcoin's safe confirmation depth
//! and reorg-halt bound are explicitly OPEN security/ops decisions
//! (docs/threat-model.md), not something this code may quietly assume.
//!
//! Nothing here ever reads a credential's VALUE into a log line or an error
//! message — only presence/shape is validated.

use std::path::PathBuf;

use thiserror::Error;

use super::hex;

/// Exact byte length of a well-formed P2PKH `scriptPubKey`:
/// `OP_DUP OP_HASH160 <push 20> <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
const P2PKH_SCRIPT_LEN: usize = 25;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must be valid hex: {reason}")]
    InvalidHex { field: &'static str, reason: String },
    #[error("{field} must be exactly {expected} bytes, got {actual}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error(
        "vault_script_pubkey_hex must be a P2PKH script (76a914<20 bytes>88ac, {P2PKH_SCRIPT_LEN} bytes); \
         P2SH/multisig vaults are not supported in Phase 4 (owner decision U5)"
    )]
    NotP2pkh,
    #[error("confirmation_depth must be greater than zero")]
    ZeroConfirmationDepth,
    #[error(
        "max_reorg_depth ({max_reorg_depth}) must be >= confirmation_depth ({confirmation_depth})"
    )]
    ReorgDepthTooSmall {
        max_reorg_depth: u32,
        confirmation_depth: u32,
    },
    #[error("rolling_window_cap_atomic requires a nonzero rolling_window_seconds")]
    RollingWindowMisconfigured,
}

/// Decodes hex into exactly `N` bytes, or a [`ConfigError`] naming `field`.
/// Thin wrapper over [`hex::decode_exact`] that maps its errors onto
/// field-attributed [`ConfigError`] variants.
fn decode_hex_exact<const N: usize>(field: &'static str, s: &str) -> Result<[u8; N], ConfigError> {
    if s.is_empty() {
        return Err(ConfigError::Empty { field });
    }
    hex::decode_exact::<N>(s).map_err(|e| match e {
        hex::HexError::WrongLength {
            expected, actual, ..
        } => ConfigError::WrongLength {
            field,
            expected,
            actual,
        },
        other => ConfigError::InvalidHex {
            field,
            reason: other.to_string(),
        },
    })
}

/// Goldcoin RPC connection details. Credentials are read by the caller from
/// the environment (never hardcoded, never logged) and passed in already
/// resolved — this struct does no I/O of its own.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
}

/// Rolling-window value cap (threat-model.md's "rolling-window value caps"
/// mitigation), in addition to an optional flat per-deposit cap.
#[derive(Debug, Clone, Copy)]
pub struct ValueCaps {
    /// `None` = no per-deposit ceiling.
    pub max_deposit_atomic: Option<u64>,
    /// `None` = no rolling-window ceiling.
    pub rolling_window: Option<RollingWindow>,
}

#[derive(Debug, Clone, Copy)]
pub struct RollingWindow {
    pub window_seconds: u64,
    pub cap_atomic: u64,
}

/// Fully validated Phase 4 indexer configuration. The only way to obtain one
/// is [`IndexerConfig::validate`], which enforces every startup invariant
/// this module documents.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub rpc: RpcConfigValidated,
    pub db_path: PathBuf,
    pub vault_script_pubkey: [u8; P2PKH_SCRIPT_LEN],
    pub confirmation_depth: u32,
    pub max_reorg_depth: u32,
    pub min_deposit_atomic: u64,
    pub value_caps: ValueCaps,
    pub protocol_version: u8,
    pub program_id: [u8; 32],
    pub validator_epoch: u64,
    pub wrapped_mint: [u8; 32],
    /// How long to sleep between ticks when the node is unreachable
    /// (distinct from the RPC client's own short-blip retry, see rpc.rs).
    pub node_unavailable_retry_interval_ms: u64,
    /// Normal steady-state tick interval.
    pub poll_interval_ms: u64,
}

/// [`RpcConfig`] after shape validation (non-empty URL/user/password).
#[derive(Debug, Clone)]
pub struct RpcConfigValidated {
    pub url: String,
    pub user: String,
    pub password: String,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
}

/// Raw, pre-validation input — typically assembled from environment
/// variables or a config file by the binary's entrypoint.
pub struct RawIndexerConfig {
    pub rpc: RpcConfig,
    pub db_path: PathBuf,
    /// Hex-encoded `scriptPubKey`, e.g. from `validateaddress`'s
    /// `scriptPubKey` field for the vault's P2PKH address.
    pub vault_script_pubkey_hex: String,
    pub confirmation_depth: u32,
    pub max_reorg_depth: u32,
    pub min_deposit_atomic: u64,
    pub value_caps: ValueCaps,
    pub protocol_version: u8,
    pub program_id_hex: String,
    pub validator_epoch: u64,
    pub wrapped_mint_hex: String,
    pub node_unavailable_retry_interval_ms: u64,
    pub poll_interval_ms: u64,
}

impl IndexerConfig {
    /// Validates every field, returning the first violation encountered.
    /// Called once at process startup; the binary refuses to run on error.
    pub fn validate(raw: RawIndexerConfig) -> Result<Self, ConfigError> {
        if raw.rpc.url.is_empty() {
            return Err(ConfigError::Empty { field: "rpc.url" });
        }
        if raw.rpc.user.is_empty() {
            return Err(ConfigError::Empty { field: "rpc.user" });
        }
        if raw.rpc.password.is_empty() {
            return Err(ConfigError::Empty {
                field: "rpc.password",
            });
        }

        let vault_script_pubkey: [u8; P2PKH_SCRIPT_LEN] =
            decode_hex_exact("vault_script_pubkey_hex", &raw.vault_script_pubkey_hex)?;
        if !is_p2pkh(&vault_script_pubkey) {
            return Err(ConfigError::NotP2pkh);
        }

        if raw.confirmation_depth == 0 {
            return Err(ConfigError::ZeroConfirmationDepth);
        }
        if raw.max_reorg_depth < raw.confirmation_depth {
            return Err(ConfigError::ReorgDepthTooSmall {
                max_reorg_depth: raw.max_reorg_depth,
                confirmation_depth: raw.confirmation_depth,
            });
        }

        if let Some(w) = raw.value_caps.rolling_window {
            if w.window_seconds == 0 {
                return Err(ConfigError::RollingWindowMisconfigured);
            }
        }

        let program_id: [u8; 32] = decode_hex_exact("program_id_hex", &raw.program_id_hex)?;
        let wrapped_mint: [u8; 32] = decode_hex_exact("wrapped_mint_hex", &raw.wrapped_mint_hex)?;

        Ok(IndexerConfig {
            rpc: RpcConfigValidated {
                url: raw.rpc.url,
                user: raw.rpc.user,
                password: raw.rpc.password,
                connect_timeout_ms: raw.rpc.connect_timeout_ms,
                read_timeout_ms: raw.rpc.read_timeout_ms,
            },
            db_path: raw.db_path,
            vault_script_pubkey,
            confirmation_depth: raw.confirmation_depth,
            max_reorg_depth: raw.max_reorg_depth,
            min_deposit_atomic: raw.min_deposit_atomic,
            value_caps: raw.value_caps,
            protocol_version: raw.protocol_version,
            program_id,
            validator_epoch: raw.validator_epoch,
            wrapped_mint,
            node_unavailable_retry_interval_ms: raw.node_unavailable_retry_interval_ms,
            poll_interval_ms: raw.poll_interval_ms,
        })
    }
}

fn is_p2pkh(script: &[u8; P2PKH_SCRIPT_LEN]) -> bool {
    script[0] == 0x76 // OP_DUP
        && script[1] == 0xa9 // OP_HASH160
        && script[2] == 0x14 // push 20 bytes
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xac // OP_CHECKSIG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_p2pkh_hex() -> String {
        // 76a914 <20-byte hash> 88ac — the real shape observed against a
        // live Goldcoin regtest node in this session.
        format!("76a914{}88ac", "11".repeat(20))
    }

    fn base_raw() -> RawIndexerConfig {
        RawIndexerConfig {
            rpc: RpcConfig {
                url: "http://127.0.0.1:18122".into(),
                user: "testuser".into(),
                password: "testpass".into(),
                connect_timeout_ms: 5_000,
                read_timeout_ms: 30_000,
            },
            db_path: PathBuf::from(":memory:"),
            vault_script_pubkey_hex: valid_p2pkh_hex(),
            confirmation_depth: 2,
            max_reorg_depth: 10,
            min_deposit_atomic: 1_000,
            value_caps: ValueCaps {
                max_deposit_atomic: Some(1_000_000_000),
                rolling_window: Some(RollingWindow {
                    window_seconds: 3600,
                    cap_atomic: 10_000_000_000,
                }),
            },
            protocol_version: 1,
            program_id_hex: "22".repeat(32),
            validator_epoch: 0,
            wrapped_mint_hex: "33".repeat(32),
            node_unavailable_retry_interval_ms: 5_000,
            poll_interval_ms: 1_000,
        }
    }

    #[test]
    fn accepts_well_formed_config() {
        let cfg = IndexerConfig::validate(base_raw()).expect("should validate");
        assert_eq!(cfg.confirmation_depth, 2);
        assert_eq!(cfg.max_reorg_depth, 10);
        assert_eq!(cfg.program_id, [0x22; 32]);
        assert_eq!(cfg.wrapped_mint, [0x33; 32]);
        assert!(is_p2pkh(&cfg.vault_script_pubkey));
    }

    #[test]
    fn rejects_zero_confirmation_depth() {
        let mut raw = base_raw();
        raw.confirmation_depth = 0;
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::ZeroConfirmationDepth
        );
    }

    #[test]
    fn rejects_max_reorg_depth_below_confirmation_depth() {
        let mut raw = base_raw();
        raw.confirmation_depth = 5;
        raw.max_reorg_depth = 4;
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::ReorgDepthTooSmall {
                max_reorg_depth: 4,
                confirmation_depth: 5,
            }
        );
    }

    #[test]
    fn accepts_max_reorg_depth_equal_to_confirmation_depth() {
        let mut raw = base_raw();
        raw.confirmation_depth = 5;
        raw.max_reorg_depth = 5;
        assert!(IndexerConfig::validate(raw).is_ok());
    }

    #[test]
    fn rejects_non_p2pkh_vault_script() {
        let mut raw = base_raw();
        // A P2SH script (OP_HASH160 <push20> OP_EQUAL) — deliberately not P2PKH.
        raw.vault_script_pubkey_hex = format!("a914{}87", "11".repeat(20));
        // Wrong length entirely (23 bytes vs 25) is also rejected, but to
        // isolate the P2PKH-shape check, pad to 25 bytes with a non-matching
        // trailer instead.
        raw.vault_script_pubkey_hex = format!("76a914{}876c", "11".repeat(20));
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::NotP2pkh
        );
    }

    #[test]
    fn rejects_wrong_length_vault_script() {
        let mut raw = base_raw();
        raw.vault_script_pubkey_hex = "76a914".to_string(); // truncated
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::WrongLength {
                field: "vault_script_pubkey_hex",
                expected: P2PKH_SCRIPT_LEN * 2,
                actual: 6,
            }
        );
    }

    #[test]
    fn rejects_invalid_hex() {
        let mut raw = base_raw();
        raw.program_id_hex = "zz".repeat(32);
        assert!(matches!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::InvalidHex { field, .. } if field == "program_id_hex"
        ));
    }

    #[test]
    fn rejects_empty_rpc_credentials() {
        let mut raw = base_raw();
        raw.rpc.password = String::new();
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::Empty {
                field: "rpc.password"
            }
        );
    }

    #[test]
    fn rejects_rolling_window_with_zero_duration() {
        let mut raw = base_raw();
        raw.value_caps.rolling_window = Some(RollingWindow {
            window_seconds: 0,
            cap_atomic: 1,
        });
        assert_eq!(
            IndexerConfig::validate(raw).unwrap_err(),
            ConfigError::RollingWindowMisconfigured
        );
    }

    #[test]
    fn accepts_no_value_caps() {
        let mut raw = base_raw();
        raw.value_caps = ValueCaps {
            max_deposit_atomic: None,
            rolling_window: None,
        };
        assert!(IndexerConfig::validate(raw).is_ok());
    }
}
