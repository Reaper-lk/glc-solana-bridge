//! `signer-server` — one validator's isolated signing service (Phase 7d,
//! ADR-0016).
//!
//! This process holds **exactly one** validator's ed25519 private key and is
//! the only process in the deployment that holds any. The relayer daemon
//! (`glc-relayer`) holds none: it asks this service, over mutually
//! authenticated TLS, and aggregates what comes back. Only signatures
//! traverse the network — never key material, and never the authority to
//! decide what should be signed.
//!
//! # What it will and will not sign
//!
//! Every request is answered from this validator's **own** database. The
//! canonical message is re-derived through the same reload-and-recompute
//! safeguards the locally-driven pipelines use (`p2p::view`), and the
//! requester's copy of the bytes is only ever compared against it. A fully
//! compromised requester therefore cannot induce a signature over anything
//! this validator has not itself observed and verified.
//!
//! # It fails closed, at startup and at runtime
//!
//! Startup aborts unless every piece of configuration is present and valid,
//! the TLS material loads, and the on-chain validator epoch can actually be
//! read. At runtime, if epoch polling stops succeeding, the view goes stale
//! and every request is refused until the link recovers — a signer that
//! cannot see the chain must not authorize under a federation revision it
//! may have fallen behind.

use std::path::PathBuf;
use std::sync::Arc;

use solana_sdk::pubkey::Pubkey;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use glc_relayer::glc::db::Db;
use glc_relayer::p2p::identity::{TlsMaterial, TlsPaths};
use glc_relayer::p2p::service::pb::federation_signer_server::FederationSignerServer;
use glc_relayer::p2p::service::SignerService;
use glc_relayer::p2p::view::{DbLocalView, EpochObservation, EPOCH_POLL_INTERVAL};
use glc_relayer::signer::load_validator_keypair;
use glc_relayer::solana::instruction;
use glc_relayer::solana::rpc::{self, RealSolanaRpc, SolanaRpc};

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reads the on-chain validator epoch — this validator's own observation,
/// never a configured constant.
async fn observe_epoch(solana_rpc: &RealSolanaRpc, program_id: &Pubkey) -> anyhow::Result<u64> {
    let (validator_set_pda, _) = instruction::validator_set_pda(program_id);
    let account = solana_rpc
        .get_account(&validator_set_pda)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the on-chain ValidatorSet account was not found — has the bridge been initialized?"
            )
        })?;
    Ok(rpc::decode_validator_set(&account.data)?.epoch)
}

/// Re-observes the epoch until shutdown.
///
/// A failed poll deliberately leaves the last observation untouched rather
/// than substituting a guess: staleness then accumulates and the view stops
/// answering on its own, which is the intended behaviour.
async fn run_epoch_refresher(
    solana_rpc: RealSolanaRpc,
    program_id: Pubkey,
    observation: Arc<EpochObservation>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("epoch refresher: shutdown signal received, exiting");
                return;
            }
            _ = tokio::time::sleep(EPOCH_POLL_INTERVAL) => {
                match observe_epoch(&solana_rpc, &program_id).await {
                    Ok(epoch) => {
                        let previous = observation.epoch();
                        observation.record(epoch, now_unix());
                        if epoch != previous {
                            tracing::warn!(
                                previous,
                                observed = epoch,
                                "validator set epoch changed — requests quoting the old epoch will now be refused"
                            );
                        }
                    }
                    Err(e) => {
                        // Not an error to exit on: the staleness bound is
                        // what protects correctness here, and a signer that
                        // died on a transient RPC blip would be worse for
                        // availability than one that briefly refuses.
                        tracing::warn!(
                            error = %e,
                            "failed to re-observe the validator epoch; this signer will refuse requests once its view goes stale"
                        );
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

    // This process's single validator identity. Singular by design: holding
    // more than one federation identity in one process is the bootstrap
    // topology Phase 7c retired.
    let keypair = load_validator_keypair(PathBuf::from(env_required(
        "GLC_SIGNER_VALIDATOR_KEYPAIR_PATH",
    )?))?;
    let validator_pubkey = solana_sdk::signature::Signer::pubkey(&keypair);

    let listen: std::net::SocketAddr = env_required("GLC_SIGNER_LISTEN_ADDR")?
        .parse()
        .map_err(|e| anyhow::anyhow!("GLC_SIGNER_LISTEN_ADDR must be host:port: {e}"))?;

    // TLS material. Loaded before anything else opens a socket, and fails
    // closed: a signer without the means to authenticate its peers would be
    // serving signatures to anyone who can reach the port.
    let tls = TlsMaterial::load(&TlsPaths {
        ca: PathBuf::from(env_required("GLC_FEDERATION_CA_CERT_PATH")?),
        cert: PathBuf::from(env_required("GLC_SIGNER_TLS_CERT_PATH")?),
        key: PathBuf::from(env_required("GLC_SIGNER_TLS_KEY_PATH")?),
    })?;

    let program_id: Pubkey = {
        let hex = env_required("GLC_PROGRAM_ID_HEX")?;
        let bytes = glc_relayer::glc::hex::decode_exact::<32>(&hex)
            .map_err(|e| anyhow::anyhow!("GLC_PROGRAM_ID_HEX is not 32 hex-encoded bytes: {e}"))?;
        Pubkey::from(bytes)
    };
    let commitment =
        glc_relayer::solana::config::parse_commitment(&env_required("GLC_SOLANA_COMMITMENT")?)
            .map_err(|e| anyhow::anyhow!("invalid GLC_SOLANA_COMMITMENT: {e}"))?;
    let solana_rpc = RealSolanaRpc::new(env_required("GLC_SOLANA_RPC_URL")?, commitment);

    // Fail closed at startup: a signer that has never observed the epoch has
    // nothing meaningful to compare a request against, so it must not begin
    // serving at all.
    let epoch = observe_epoch(&solana_rpc, &program_id).await.map_err(|e| {
        anyhow::anyhow!("refusing to start without a first observation of the validator epoch: {e}")
    })?;
    let observation = Arc::new(EpochObservation::seeded(epoch, now_unix()));

    // The signer's own database — its independent record of the chain. The
    // same file the local indexer writes; a second connection, as everywhere
    // else in this codebase (WAL mode + busy timeout).
    let db = Db::open(&PathBuf::from(env_required("GLC_DB_PATH")?))?;
    let view = DbLocalView::new(db, Arc::clone(&observation));
    let service = SignerService::new(keypair, view);

    tracing::info!(
        validator = %validator_pubkey,
        %listen,
        program_id = %program_id,
        observed_epoch = epoch,
        "signer-server: starting (mTLS, pinned federation CA)"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let refresher = tokio::spawn(run_epoch_refresher(
        RealSolanaRpc::new(
            std::env::var("GLC_SOLANA_RPC_URL").unwrap_or_default(),
            commitment,
        ),
        program_id,
        observation,
        shutdown_rx,
    ));

    let tls_config = ServerTlsConfig::new()
        .identity(Identity::from_pem(&tls.cert_pem, &tls.key_pem))
        // Requiring a client certificate signed by the federation CA is what
        // makes this mutual rather than merely encrypted: without it, anyone
        // who can reach the port could ask this validator to sign.
        .client_ca_root(Certificate::from_pem(&tls.ca_pem));

    let serve = Server::builder()
        .tls_config(tls_config)?
        .add_service(FederationSignerServer::new(service))
        .serve_with_shutdown(listen, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("signer-server: shutdown signal received");
        });

    let result = serve.await;
    let _ = shutdown_tx.send(true);
    let _ = refresher.await;
    result.map_err(|e| anyhow::anyhow!("signer-server transport error: {e}"))?;
    Ok(())
}
