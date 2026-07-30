//! glc-relayer — federated validator daemon.
//!
//! Phase 4 wires up the Goldcoin indexer (`glc` module): it follows the
//! chain, detects vault deposits, tracks confirmations, and produces
//! unsigned canonical claim artifacts once a deposit reaches
//! `ReadyForSignature`. It does not sign, aggregate signatures, submit to
//! Solana, or move any value — those remain Phase 5+ (`signer`, `p2p`,
//! `solana` modules).
//!
//! All configuration — including RPC credentials — comes from the
//! environment, never from a committed file (see `.gitignore` and
//! docs/goldcoin-rpc-notes.md). Every value is validated strictly at
//! startup (`glc::config::IndexerConfig::validate`); the process refuses to
//! run on a misconfiguration rather than guessing.

use std::path::PathBuf;
use std::time::Duration;

use glc_relayer::glc;
use glc_relayer::glc::config::{
    IndexerConfig, RawIndexerConfig, RollingWindow, RpcConfig, ValueCaps,
};
use glc_relayer::glc::db::Db;
use glc_relayer::glc::indexer::{Indexer, TickOutcome};
use glc_relayer::glc::rpc::RpcClient;

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

fn env_optional_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{name} must be a u64: {e}")),
        Err(_) => Ok(default),
    }
}

fn env_required_u64(name: &str) -> anyhow::Result<u64> {
    env_required(name)?
        .parse()
        .map_err(|e| anyhow::anyhow!("{name} must be a u64: {e}"))
}

fn env_required_u32(name: &str) -> anyhow::Result<u32> {
    env_required(name)?
        .parse()
        .map_err(|e| anyhow::anyhow!("{name} must be a u32: {e}"))
}

/// Assembles [`RawIndexerConfig`] from environment variables. Kept separate
/// from `main` so its (extensive) env-var contract is easy to find and unit
/// test independently of process I/O.
fn config_from_env() -> anyhow::Result<IndexerConfig> {
    let max_deposit_atomic = match std::env::var("GLC_MAX_DEPOSIT_ATOMIC") {
        Ok(v) => Some(
            v.parse::<u64>()
                .map_err(|e| anyhow::anyhow!("GLC_MAX_DEPOSIT_ATOMIC must be a u64: {e}"))?,
        ),
        Err(_) => None,
    };
    let rolling_window = match (
        std::env::var("GLC_ROLLING_WINDOW_SECONDS").ok(),
        std::env::var("GLC_ROLLING_WINDOW_CAP_ATOMIC").ok(),
    ) {
        (Some(w), Some(c)) => Some(RollingWindow {
            window_seconds: w
                .parse()
                .map_err(|e| anyhow::anyhow!("GLC_ROLLING_WINDOW_SECONDS must be a u64: {e}"))?,
            cap_atomic: c
                .parse()
                .map_err(|e| anyhow::anyhow!("GLC_ROLLING_WINDOW_CAP_ATOMIC must be a u64: {e}"))?,
        }),
        (None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "GLC_ROLLING_WINDOW_SECONDS and GLC_ROLLING_WINDOW_CAP_ATOMIC must be set together"
            ))
        }
    };

    let raw = RawIndexerConfig {
        rpc: RpcConfig {
            url: env_required("GLC_RPC_URL")?,
            user: env_required("GLC_RPC_USER")?,
            password: env_required("GLC_RPC_PASSWORD")?,
            connect_timeout_ms: env_optional_u64("GLC_RPC_CONNECT_TIMEOUT_MS", 5_000)?,
            read_timeout_ms: env_optional_u64("GLC_RPC_READ_TIMEOUT_MS", 30_000)?,
        },
        db_path: PathBuf::from(env_required("GLC_DB_PATH")?),
        vault_script_pubkey_hex: env_required("GLC_VAULT_SCRIPT_PUBKEY_HEX")?,
        // No built-in production default (owner decision U6): Goldcoin's
        // safe confirmation depth and reorg-halt bound are open security/ops
        // decisions (docs/threat-model.md), never silently assumed here.
        confirmation_depth: env_required_u32("GLC_CONFIRMATION_DEPTH")?,
        max_reorg_depth: env_required_u32("GLC_MAX_REORG_DEPTH")?,
        // 0 = disabled, consistent with the on-chain min_deposit convention;
        // the on-chain check remains the final enforcement either way (U3).
        min_deposit_atomic: env_optional_u64("GLC_MIN_DEPOSIT_ATOMIC", 0)?,
        value_caps: ValueCaps {
            max_deposit_atomic,
            rolling_window,
        },
        protocol_version: env_required("GLC_PROTOCOL_VERSION")?
            .parse()
            .map_err(|e| anyhow::anyhow!("GLC_PROTOCOL_VERSION must be a u8: {e}"))?,
        program_id_hex: env_required("GLC_PROGRAM_ID_HEX")?,
        validator_epoch: env_required_u64("GLC_VALIDATOR_EPOCH")?,
        wrapped_mint_hex: env_required("GLC_WRAPPED_MINT_HEX")?,
        node_unavailable_retry_interval_ms: env_optional_u64(
            "GLC_NODE_UNAVAILABLE_RETRY_INTERVAL_MS",
            5_000,
        )?,
        poll_interval_ms: env_optional_u64("GLC_POLL_INTERVAL_MS", 1_000)?,
    };

    IndexerConfig::validate(raw).map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = config_from_env()?;
    tracing::info!(
        confirmation_depth = config.confirmation_depth,
        max_reorg_depth = config.max_reorg_depth,
        min_deposit_atomic = config.min_deposit_atomic,
        "glc-relayer Phase 4: starting Goldcoin indexer"
    );

    let db = Db::open(&config.db_path)?;
    tracing::info!(schema_version = db.schema_version()?, "database ready");
    let rpc = RpcClient::new(&config.rpc)?;
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let unavailable_interval = Duration::from_millis(config.node_unavailable_retry_interval_ms);
    let mut indexer = Indexer::new(rpc, db, config);

    let mut shutdown = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, exiting");
                return Ok(());
            }
            result = indexer.tick() => {
                match result {
                    Ok(TickOutcome::Progressed { blocks_indexed, reorg }) => {
                        if let Some(r) = reorg {
                            tracing::warn!(
                                fork_height = r.fork_height,
                                old_tip_height = r.old_tip_height,
                                orphaned_count = r.orphaned_count,
                                "reorg detected and rolled back"
                            );
                        }
                        if blocks_indexed > 0 {
                            tracing::info!(blocks_indexed, "indexed new blocks");
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    Ok(TickOutcome::Halted { attempted_depth }) => {
                        tracing::error!(
                            attempted_depth,
                            "reorg deeper than max_reorg_depth: indexer halted, manual intervention required"
                        );
                        // Process stays alive (for liveness probes/orchestration)
                        // but performs no further indexing work.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                    Err(glc::indexer::IndexerError::NodeUnavailable(e)) => {
                        tracing::warn!(error = %e, "Goldcoin node unavailable, retrying");
                        tokio::time::sleep(unavailable_interval).await;
                    }
                    Err(glc::indexer::IndexerError::Rpc(e)) => {
                        tracing::error!(error = %e, "Goldcoin RPC method error this tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(glc::indexer::IndexerError::Db(e)) => {
                        tracing::error!(error = %e, "database error — exiting");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
