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

use glc_relayer::glc::config::RpcConfigValidated;
use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::{PrevTx, RpcClient};
use glc_relayer::p2p::completion_view::CompletionView;
use glc_relayer::p2p::identity::{TlsMaterial, TlsPaths};
use glc_relayer::p2p::payout_view::{PartialSigner, PayoutView};
use glc_relayer::p2p::service::pb::federation_signer_server::FederationSignerServer;
use glc_relayer::p2p::service::SignerService;
use glc_relayer::p2p::view::DbLocalView;
use glc_relayer::signer::load_validator_keypair;
use glc_relayer::solana::epoch::{observe_epoch, run_epoch_refresher, EpochObservation};
use glc_relayer::solana::rpc::RealSolanaRpc;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::assignment::OperatorAssignment;
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Signs with **this signer's single vault key**, on **this signer's own**
/// Goldcoin node (Phase 7e, ADR-0017 E2).
///
/// A partial M-of-N signature legitimately comes back with
/// `complete: false` — that is the expected result of contributing one of M
/// signatures, not a failure, so it is passed through rather than treated as
/// an error.
struct NodePartialSigner {
    rpc: RpcClient,
    wif: String,
}

impl PartialSigner for NodePartialSigner {
    async fn sign_partial(
        &self,
        unsigned_tx_hex: &str,
        prevtxs: &[PrevTx],
    ) -> Result<String, String> {
        self.rpc
            .sign_raw_transaction_with_prevtxs(
                unsigned_tx_hex,
                prevtxs,
                Some(std::slice::from_ref(&self.wif)),
            )
            .await
            .map(|r| r.hex)
            .map_err(|e| e.to_string())
    }
}

/// Builds the vault-signing arm, or explains why this signer has none.
///
/// **Fails closed** (ADR-0017 E1): if a vault key is configured, the process
/// proves it actually holds the key at its configured position before
/// serving. A signer that cannot prove that refuses to start rather than
/// discovering the mismatch when a payout fails.
/// This signer's OWN Goldcoin node (ADR-0017 E2, reused by ADR-0018 D6).
///
/// Both the payout arm and the completion arm validate against it, and both
/// depend on it being independent of the relayer's node — a signer that
/// inherits the requester's view of the chain is not checking anything.
/// The validated withdrawal configuration, shared with the relayer so a
/// signer checks an adopted proposal against identical policy.
fn withdrawal_config_from_env() -> anyhow::Result<WithdrawalConfig> {
    let raw = RawWithdrawalConfig {
        vault_redeem_script_hex: env_required("GLC_VAULT_REDEEM_SCRIPT_HEX")?,
        vault_address: env_required("GLC_VAULT_ADDRESS")?,
        change_address: env_required("GLC_VAULT_CHANGE_ADDRESS")?,
        fee_rate_per_kb: env_required("GLC_PAYOUT_FEE_RATE_PER_KB")?.parse()?,
        dust_threshold_atomic: env_required("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC")?.parse()?,
        vault_min_confirmations: env_required("GLC_VAULT_MIN_CONFIRMATIONS")?.parse()?,
        confirmation_depth: env_required("GLC_WITHDRAWAL_CONFIRMATION_DEPTH")?.parse()?,
        max_inputs_per_payout: env_required("GLC_PAYOUT_MAX_INPUTS")?.parse()?,
        reservation_timeout_secs: env_required("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS")?.parse()?,
        discovery_commitment: env_required("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT")?,
        poll_interval_ms: 5_000,
    };
    WithdrawalConfig::validate(raw)
        .map_err(|e| anyhow::anyhow!("invalid withdrawal configuration: {e}"))
}

/// This operator's place in the federation (Phase 7g, ADR-0019 D1).
///
/// `None` when the federation is not configured for multi-operator running,
/// in which case the signer accepts a proposal from anyone — correct for a
/// single-operator deployment, and the historical behaviour.
fn operator_assignment_from_env() -> anyhow::Result<Option<OperatorAssignment>> {
    let (Some(index), Some(count)) = (
        env_optional("GLC_OPERATOR_INDEX"),
        env_optional("GLC_OPERATOR_COUNT"),
    ) else {
        return Ok(None);
    };
    Ok(Some(OperatorAssignment::new(
        index.parse()?,
        count.parse()?,
        env_optional("GLC_PAYOUT_BUILD_TIMEOUT_SECS")
            .unwrap_or_else(|| "120".into())
            .parse()?,
        env_optional("GLC_MINT_SUBMIT_TIMEOUT_SECS")
            .unwrap_or_else(|| "60".into())
            .parse()?,
    )?))
}

fn signer_goldcoin_rpc() -> anyhow::Result<RpcClient> {
    let url = env_required("GLC_SIGNER_GLC_RPC_URL")?;
    let user = env_required("GLC_SIGNER_GLC_RPC_USER")?;
    let password = env_required("GLC_SIGNER_GLC_RPC_PASSWORD")?;
    if url.is_empty() || user.is_empty() || password.is_empty() {
        return Err(anyhow::anyhow!(
            "GLC_SIGNER_GLC_RPC_URL, _USER and _PASSWORD must all be non-empty"
        ));
    }
    Ok(RpcClient::new(&RpcConfigValidated {
        url,
        user,
        password,
        connect_timeout_ms: 5_000,
        read_timeout_ms: 30_000,
    })?)
}

fn payout_arm() -> anyhow::Result<Option<(PayoutView<NodePartialSigner>, Db)>> {
    let Some(_redeem_hex) = env_optional("GLC_VAULT_REDEEM_SCRIPT_HEX") else {
        tracing::warn!(
            "GLC_VAULT_REDEEM_SCRIPT_HEX is not set — this signer serves MINT requests only and              will refuse every payout request"
        );
        return Ok(None);
    };
    // The signer validates an adopted proposal against the SAME policy the
    // executor builds with (ADR-0019 D3), so it loads the same validated
    // configuration rather than a subset of it.
    let cfg = withdrawal_config_from_env()?;
    let vault = cfg.vault.clone();

    let index: u8 = env_required("GLC_SIGNER_VAULT_INDEX")?
        .parse()
        .map_err(|e| anyhow::anyhow!("GLC_SIGNER_VAULT_INDEX must be a u8: {e}"))?;

    let wif = std::fs::read_to_string(env_required("GLC_SIGNER_VAULT_KEY_PATH")?)
        .map_err(|e| anyhow::anyhow!("failed to read the vault key file: {e}"))?
        .trim()
        .to_string();

    // THE E1 check: the key this process holds must be the key the vault
    // expects at the configured position.
    vault.require_signer_at(index, &wif).map_err(|e| {
        anyhow::anyhow!(
            "refusing to start: this signer's vault key does not match vault position {index} — {e}"
        )
    })?;

    // ADR-0017 E2: this MUST be the signer's own node, never the relayer's.
    // Independent validation is a core security property: a signer sharing
    // the requester's node inherits the requester's view.
    let rpc = signer_goldcoin_rpc()?;
    let rpc_url = env_required("GLC_SIGNER_GLC_RPC_URL")?;

    tracing::info!(
        vault_address = %vault.address,
        vault_signer_index = index,
        goldcoin_rpc = %rpc_url,
        "payout signing enabled — this MUST be this signer's OWN Goldcoin node (ADR-0017 E2)"
    );

    let db = Db::open(&PathBuf::from(env_required("GLC_DB_PATH")?))?;
    let mut view = PayoutView::new(cfg, index, NodePartialSigner { rpc, wif })
        .map_err(|e| anyhow::anyhow!(e))?;
    if let Some(a) = operator_assignment_from_env()? {
        view = view.with_assignment(a);
    }
    Ok(Some((view, db)))
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
    let mut service = SignerService::new(keypair, view);

    // The Goldcoin vault-signing arm (Phase 7e). Absent when this signer
    // holds no vault key, in which case every payout request is refused.
    if let Some((payout_view, payout_db)) = payout_arm()? {
        service = service.with_payout_arm(payout_view, payout_db);
    }

    // The completion-attestation arm (Phase 7f, ADR-0018). Uses the SAME
    // confirmation depth as the payout pipeline (owner decision Q2), and
    // the same own-node requirement as the payout arm (E2).
    if let Some(depth) = env_optional("GLC_WITHDRAWAL_CONFIRMATION_DEPTH") {
        let depth: i64 = depth.parse().map_err(|e| {
            anyhow::anyhow!("GLC_WITHDRAWAL_CONFIRMATION_DEPTH must be an i64: {e}")
        })?;
        let rpc = signer_goldcoin_rpc()?;
        let protocol_version: u8 = env_required("GLC_PROTOCOL_VERSION")?
            .parse()
            .map_err(|e| anyhow::anyhow!("GLC_PROTOCOL_VERSION must be a u8: {e}"))?;
        tracing::info!(
            confirmation_depth = depth,
            "completion attestation enabled (Phase 7f)"
        );
        service = service.with_completion_arm(
            CompletionView::new(RealPayoutRpc::new(rpc), depth),
            Db::open(&PathBuf::from(env_required("GLC_DB_PATH")?))?,
            program_id.to_bytes(),
            protocol_version,
        );
    } else {
        tracing::warn!(
            "GLC_WITHDRAWAL_CONFIRMATION_DEPTH is not set — this signer will refuse every \
             withdrawal completion request"
        );
    }

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
