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
use glc_relayer::p2p::collector::{GrpcCollector, PeerEndpoint};
use glc_relayer::solana::config::{RawSolanaConfig, SolanaConfig};
use glc_relayer::solana::rpc::RealSolanaRpc;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::discovery;
use glc_relayer::withdrawal::executor::{ExecutorError, WithdrawalExecutor};

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

/// Assembles [`WithdrawalConfig`] (Phase 6, ADR-0013) from environment
/// variables. Nothing here has a silent default: the fee rate (D4), the
/// confirmation depth (D7) and the discovery commitment (D5) must all be
/// stated explicitly, and the commitment must be exactly `finalized`.
fn withdrawal_config_from_env() -> anyhow::Result<WithdrawalConfig> {
    let raw = RawWithdrawalConfig {
        vault_redeem_script_hex: env_required("GLC_VAULT_REDEEM_SCRIPT_HEX")?,
        vault_address: env_required("GLC_VAULT_ADDRESS")?,
        change_address: env_required("GLC_VAULT_CHANGE_ADDRESS")?,
        fee_rate_per_kb: env_required_u64("GLC_PAYOUT_FEE_RATE_PER_KB")?,
        dust_threshold_atomic: env_required_u64("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC")?,
        vault_min_confirmations: env_required_u64("GLC_VAULT_MIN_CONFIRMATIONS")? as i64,
        confirmation_depth: env_required_u64("GLC_WITHDRAWAL_CONFIRMATION_DEPTH")? as i64,
        max_inputs_per_payout: env_required_u64("GLC_PAYOUT_MAX_INPUTS")? as usize,
        reservation_timeout_secs: env_required_u64("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS")? as i64,
        discovery_commitment: env_required("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT")?,
        poll_interval_ms: env_optional_u64("GLC_WITHDRAWAL_POLL_INTERVAL_MS", 5_000)?,
    };
    WithdrawalConfig::validate(raw)
        .map_err(|e| anyhow::anyhow!("invalid withdrawal configuration: {e}"))
}

/// The withdrawal executor's tick loop (Phase 6), the third long-running
/// service alongside the indexer and the mint orchestrator.
///
/// Discovery and execution share one task on purpose: the executor is
/// single-threaded by design (owner decision D8), so scanning Solana and
/// driving payouts are strictly sequential and no two ticks can ever
/// overlap on the same vault.
#[allow(clippy::too_many_arguments)]
async fn run_withdrawal_loop(
    mut executor: WithdrawalExecutor<RealPayoutRpc>,
    solana_rpc: RealSolanaRpc,
    program_id: Pubkey,
    config: WithdrawalConfig,
    poll_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("withdrawal loop: shutdown signal received, exiting");
                return Ok(());
            }
            result = withdrawal_tick(&mut executor, &solana_rpc, &program_id, &config) => {
                match result {
                    Ok(()) => tokio::time::sleep(poll_interval).await,
                    Err(WithdrawalTickError::Executor(ExecutorError::Db(e))) => {
                        tracing::error!(error = %e, "withdrawal database error — exiting");
                        return Err(e.into());
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "withdrawal tick failed; retrying next tick");
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum WithdrawalTickError {
    #[error("withdrawal discovery failed: {0}")]
    Discovery(#[from] glc_relayer::solana::rpc::SolanaRpcError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
}

/// One discovery + execution pass. A discovery failure is NOT fatal and does
/// not skip execution of already-known withdrawals: a Solana outage must not
/// strand payouts that were discovered before it started.
async fn withdrawal_tick(
    executor: &mut WithdrawalExecutor<RealPayoutRpc>,
    solana_rpc: &RealSolanaRpc,
    program_id: &Pubkey,
    config: &WithdrawalConfig,
) -> Result<(), WithdrawalTickError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match discovery::scan_withdrawals(solana_rpc, program_id, config.discovery_commitment, now, 0)
        .await
    {
        Ok(found) => {
            let n = executor.ingest_discovered(&found)?;
            if n > 0 {
                tracing::info!(new_withdrawals = n, "observed new withdrawal requests");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "withdrawal discovery failed; continuing with known work");
        }
    }

    let report = executor.tick().await?;
    if report.completed > 0 || report.signed > 0 || report.halted > 0 || report.failed > 0 {
        tracing::info!(
            validated = report.validated,
            awaiting_funds = report.awaiting_funds,
            built = report.built,
            signed = report.signed,
            broadcast = report.broadcast,
            confirming = report.confirming,
            completed = report.completed,
            halted = report.halted,
            failed = report.failed,
            orphaned = report.orphaned,
            "withdrawal tick"
        );
    }
    Ok(())
}

/// Parses `GLC_FEDERATION_PEERS`: comma-separated `base58pubkey@uri`.
///
/// The pubkey is the validator identity the endpoint must answer as; a
/// response claiming a different identity is discarded by the collector, so
/// a compromised endpoint cannot impersonate another federation member.
fn parse_federation_peers(raw: &str) -> anyhow::Result<Vec<PeerEndpoint>> {
    let peers: Vec<PeerEndpoint> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let (pk, uri) = entry.split_once('@').ok_or_else(|| {
                anyhow::anyhow!("federation peer {entry:?} must be formatted pubkey@uri")
            })?;
            Ok(PeerEndpoint {
                validator_pubkey: pk
                    .parse()
                    .map_err(|e| anyhow::anyhow!("peer {pk:?} is not a valid pubkey: {e}"))?,
                uri: uri.to_string(),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    if peers.is_empty() {
        return Err(anyhow::anyhow!(
            "GLC_FEDERATION_PEERS must list at least one federation peer"
        ));
    }
    Ok(peers)
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
    mut orchestrator: Orchestrator<RealSolanaRpc, GrpcCollector>,
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
    let rpc_for_payouts = config.rpc.clone();
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
    // Phase 7c (ADR-0016): this process holds NO validator key. Signatures
    // are requested from federation peers, each of which independently
    // re-derives the message before signing. The peer set is configured
    // as `pubkey@uri` pairs.
    let peers = parse_federation_peers(&env_required("GLC_FEDERATION_PEERS")?)?;
    let solana_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);
    let orchestrator_poll_interval = Duration::from_millis(solana_config.poll_interval_ms);
    let orchestrator = Orchestrator::new(
        orchestrator_db,
        solana_rpc,
        solana_config.program_id,
        submitter,
        GrpcCollector::new(peers),
    );

    // Third service: the Goldcoin withdrawal executor (Phase 6, ADR-0013).
    let withdrawal_config = withdrawal_config_from_env()?;
    tracing::info!(
        vault_address = %withdrawal_config.vault_address,
        confirmation_depth = withdrawal_config.confirmation_depth,
        fee_rate_per_kb = withdrawal_config.fee_rate_per_kb,
        "glc-relayer: starting Goldcoin withdrawal executor (regtest custody — ADR-0013)"
    );
    let withdrawal_poll_interval = Duration::from_millis(withdrawal_config.poll_interval_ms);
    let payout_rpc = RealPayoutRpc::new(RpcClient::new(&rpc_for_payouts)?);
    let withdrawal_executor =
        WithdrawalExecutor::new(Db::open(&db_path)?, payout_rpc, withdrawal_config.clone());
    let discovery_rpc = RealSolanaRpc::new(solana_config.rpc_url.clone(), solana_config.commitment);

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
        shutdown_rx.clone(),
    ));
    let mut withdrawal_task = tokio::spawn(run_withdrawal_loop(
        withdrawal_executor,
        discovery_rpc,
        solana_config.program_id,
        withdrawal_config,
        withdrawal_poll_interval,
        shutdown_rx,
    ));

    // Either an operator-requested shutdown or an unexpected exit from
    // either loop (e.g. a fatal database error) stops the other loop and
    // ends the process — a stuck task must never be left running silently
    // after its sibling has already exited.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received, stopping all three services");
            let _ = shutdown_tx.send(true);
            let (i, o, w) = tokio::join!(indexer_task, orchestrator_task, withdrawal_task);
            i??;
            o??;
            w??;
        }
        result = &mut indexer_task => {
            tracing::error!("indexer loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(orchestrator_task, withdrawal_task);
            result??;
        }
        result = &mut orchestrator_task => {
            tracing::error!("orchestrator loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(indexer_task, withdrawal_task);
            result??;
        }
        result = &mut withdrawal_task => {
            tracing::error!("withdrawal loop exited, stopping the other services");
            let _ = shutdown_tx.send(true);
            let _ = tokio::join!(indexer_task, orchestrator_task);
            result??;
        }
    }
    Ok(())
}
