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

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::read_keypair_file;

use glc_relayer::glc;
use glc_relayer::glc::config::{
    IndexerConfig, RawIndexerConfig, RollingWindow, RpcConfig, ValueCaps,
};
use glc_relayer::glc::db::Db;
use glc_relayer::glc::indexer::{Indexer, TickOutcome};
use glc_relayer::glc::rpc::RpcClient;
use glc_relayer::orchestrator::{Orchestrator, OrchestratorError};
use glc_relayer::signer;
use glc_relayer::solana::config::{RawSolanaConfig, SolanaConfig};
use glc_relayer::solana::rpc::RealSolanaRpc;

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

/// Assembles [`SolanaConfig`] (Phase 5, ADR-0012) from environment
/// variables. `program_id_bytes` comes from the already-validated
/// `GLC_PROGRAM_ID_HEX` (Phase 4) rather than a second, independently
/// configured value — the on-chain program targeted by a submitted
/// transaction must always be identical to the one embedded in the claim
/// message, and reusing the single parsed source eliminates any chance of
/// the two drifting apart.
fn solana_config_from_env(program_id_bytes: [u8; 32]) -> anyhow::Result<SolanaConfig> {
    let validator_keypair_paths: Vec<PathBuf> = env_required("GLC_SOLANA_VALIDATOR_KEYPAIR_PATHS")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();

    let raw = RawSolanaConfig {
        rpc_url: env_required("GLC_SOLANA_RPC_URL")?,
        program_id: Pubkey::from(program_id_bytes).to_string(),
        submitter_keypair_path: PathBuf::from(env_required("GLC_SOLANA_SUBMITTER_KEYPAIR_PATH")?),
        validator_keypair_paths,
        // No built-in default (owner decision R3): the confirmation
        // commitment level must be explicit in configuration.
        commitment: env_required("GLC_SOLANA_COMMITMENT")?,
        poll_interval_ms: env_optional_u64("GLC_SOLANA_POLL_INTERVAL_MS", 2_000)?,
    };

    SolanaConfig::validate(raw).map_err(|e| anyhow::anyhow!("invalid Solana configuration: {e}"))
}

/// The Goldcoin indexer's tick loop (Phase 4), run as an independent task
/// alongside the orchestrator's so a stall or restart of one side never
/// blocks the other.
async fn run_indexer_loop(
    mut indexer: Indexer<RpcClient>,
    poll_interval: Duration,
    unavailable_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("indexer loop: shutdown signal received, exiting");
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
                        tracing::error!(error = %e, "indexer database error — exiting");
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

/// The Phase 5 mint pipeline's tick loop, run independently of the indexer
/// so Solana RPC outages never stall Goldcoin chain-following and vice
/// versa. Both loops read/write the same SQLite file through their own
/// connection (`Db::open` enables WAL mode + a busy timeout for exactly
/// this overlap).
async fn run_orchestrator_loop(
    mut orchestrator: Orchestrator<RealSolanaRpc>,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("orchestrator loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = orchestrator.tick() => {
                match result {
                    Ok(report) => {
                        if report.minted > 0 || report.submitted > 0 || report.halted > 0 {
                            tracing::info!(
                                minted = report.minted,
                                submitted = report.submitted,
                                insufficient = report.insufficient,
                                halted = report.halted,
                                "orchestrator tick"
                            );
                        }
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(OrchestratorError::NodeUnavailable(e)) => {
                        tracing::warn!(error = %e, "Solana node unavailable, retrying");
                        tokio::time::sleep(poll_interval).await;
                    }
                    Err(OrchestratorError::Db(e)) => {
                        tracing::error!(error = %e, "orchestrator database error — exiting");
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "orchestrator error this tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }
    }
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
        "glc-relayer: starting Goldcoin indexer"
    );

    let db = Db::open(&config.db_path)?;
    tracing::info!(schema_version = db.schema_version()?, "database ready");
    let rpc = RpcClient::new(&config.rpc)?;
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let unavailable_interval = Duration::from_millis(config.node_unavailable_retry_interval_ms);
    let program_id_bytes = config.program_id;
    let db_path = config.db_path.clone();
    let indexer = Indexer::new(rpc, db, config);

    let solana_config = solana_config_from_env(program_id_bytes)?;
    tracing::info!(
        program_id = %solana_config.program_id,
        commitment = ?solana_config.commitment,
        validator_count = solana_config.validator_keypair_paths.len(),
        "glc-relayer: starting Solana mint orchestrator (ADR-0012)"
    );
    // A second, independent connection to the same SQLite file (Db::open
    // enables WAL mode + a busy timeout for exactly this overlap) — the
    // indexer and orchestrator loops run concurrently and must not share
    // one connection across two tasks.
    let orchestrator_db = Db::open(&db_path)?;
    let submitter = read_keypair_file(&solana_config.submitter_keypair_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read submitter keypair {}: {e}",
            solana_config.submitter_keypair_path.display()
        )
    })?;
    let validator_keys = signer::load_validator_keypairs(&solana_config.validator_keypair_paths)?;
    let solana_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);
    let orchestrator_poll_interval = Duration::from_millis(solana_config.poll_interval_ms);
    let orchestrator = Orchestrator::new(
        orchestrator_db,
        solana_rpc,
        solana_config.program_id,
        submitter,
        validator_keys,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut indexer_task = tokio::spawn(run_indexer_loop(
        indexer,
        poll_interval,
        unavailable_interval,
        shutdown_rx.clone(),
    ));
    let mut orchestrator_task = tokio::spawn(run_orchestrator_loop(
        orchestrator,
        orchestrator_poll_interval,
        shutdown_rx,
    ));

    // Either an operator-requested shutdown or an unexpected exit from
    // either loop (e.g. a fatal database error) stops the other loop and
    // ends the process — a stuck task must never be left running silently
    // after its sibling has already exited.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received, stopping both loops");
            let _ = shutdown_tx.send(true);
            let (indexer_result, orchestrator_result) = tokio::join!(indexer_task, orchestrator_task);
            indexer_result??;
            orchestrator_result??;
        }
        result = &mut indexer_task => {
            tracing::error!("indexer loop exited, stopping orchestrator loop");
            let _ = shutdown_tx.send(true);
            let _ = orchestrator_task.await;
            result??;
        }
        result = &mut orchestrator_task => {
            tracing::error!("orchestrator loop exited, stopping indexer loop");
            let _ = shutdown_tx.send(true);
            let _ = indexer_task.await;
            result??;
        }
    }
    Ok(())
}
