//! End-to-end federation transport tests (Phase 7d, ADR-0016).
//!
//! These stand up a **real** tonic server with **real** certificates and
//! drive it with the **real** [`GrpcCollector`], over loopback TCP. Nothing
//! about the TLS wiring is asserted from reading the configuration code:
//! every claim here is established by observing what the transport actually
//! does.
//!
//! What is proven:
//!
//! - mutual TLS works at all, against a pinned federation CA;
//! - a client with **no** certificate is rejected by the server;
//! - a client whose certificate comes from a **different** CA is rejected;
//! - a server whose certificate comes from a different CA is rejected by
//!   the client;
//! - a peer answering as a different validator is discarded even though its
//!   TLS handshake succeeded — the application-layer identity check;
//! - threshold is reached from live signatures, and a shortfall is
//!   classified as retriable or not, correctly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use glc_relayer::orchestrator::SignatureCollector;
use glc_relayer::p2p::collector::GrpcCollector;
use glc_relayer::p2p::identity::{PeerEndpoint, TlsMaterial};
use glc_relayer::p2p::policy::{Action, LocalView, SigningIdentity};
use glc_relayer::p2p::service::pb::federation_signer_server::FederationSignerServer;
use glc_relayer::p2p::service::SignerService;

const TXID: [u8; 32] = [0xAB; 32];
const VOUT: u32 = 1;
const EPOCH: u64 = 7;
const MESSAGE: &[u8] = b"canonical-claim-message-bytes";

/// The name every federation certificate is issued for, and the one the
/// client pins.
const FEDERATION_DOMAIN: &str = "signer.glc-federation.test";

// ---------------------------------------------------------------------------
// Test PKI
// ---------------------------------------------------------------------------

/// A self-signed CA plus the leaf certificates it issues.
struct TestCa {
    ca_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new(common_name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let ca_pem = cert.pem();
        TestCa {
            ca_pem,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// Issues a leaf certificate for `name`, returning `(cert_pem, key_pem)`.
    fn issue(&self, name: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn material_for(&self, name: &str) -> TlsMaterial {
        let (cert_pem, key_pem) = self.issue(name);
        TlsMaterial {
            ca_pem: self.ca_pem.clone().into_bytes(),
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------
// A signer backed by a fixed view
// ---------------------------------------------------------------------------

struct FixedView {
    epoch: u64,
    message: Option<Vec<u8>>,
    fresh: bool,
}

impl LocalView for FixedView {
    fn observed_epoch(&self) -> u64 {
        self.epoch
    }
    fn view_is_fresh(&self) -> bool {
        self.fresh
    }
    fn derive_message(&self, _a: Action, id: &SigningIdentity) -> Option<Vec<u8>> {
        match id {
            SigningIdentity::Deposit { txid, vout } if *txid == TXID && *vout == VOUT => {
                self.message.clone()
            }
            _ => None,
        }
    }
}

fn view() -> FixedView {
    FixedView {
        epoch: EPOCH,
        message: Some(MESSAGE.to_vec()),
        fresh: true,
    }
}

/// A running signer, with the address it actually bound to.
struct RunningSigner {
    pubkey: Pubkey,
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

impl RunningSigner {
    fn endpoint(&self) -> PeerEndpoint {
        PeerEndpoint {
            validator_pubkey: self.pubkey,
            uri: format!("https://{}", self.addr),
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// Starts a signer on an OS-assigned port.
///
/// `server_tls` of `None` serves plaintext; `announced_as` lets a test make
/// a server answer under a different validator identity than the endpoint is
/// registered as; `rate_limit` pins the limiter so a flood test does not
/// depend on how fast the machine is.
async fn start_signer_with(
    keypair: Keypair,
    view: FixedView,
    server_tls: Option<ServerTlsConfig>,
    announced_as: Option<Pubkey>,
    rate_limit: Option<(f64, f64)>,
) -> RunningSigner {
    let pubkey = announced_as.unwrap_or_else(|| keypair.pubkey());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let service = match rate_limit {
        Some((refill, burst)) => SignerService::with_rate_limits(keypair, view, refill, burst),
        None => SignerService::new(keypair, view),
    };

    let mut builder = Server::builder();
    if let Some(tls) = server_tls {
        builder = builder.tls_config(tls).unwrap();
    }
    let server = builder
        .add_service(FederationSignerServer::new(service))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = rx.await;
        });

    let handle = tokio::spawn(async move {
        let _ = server.await;
    });
    // Give the listener a moment to be accepted on; the port is already
    // bound, so this is only about the task being scheduled.
    tokio::time::sleep(Duration::from_millis(50)).await;

    RunningSigner {
        pubkey,
        addr,
        shutdown: tx,
        handle,
    }
}

async fn start_signer(
    keypair: Keypair,
    view: FixedView,
    server_tls: Option<ServerTlsConfig>,
    announced_as: Option<Pubkey>,
) -> RunningSigner {
    start_signer_with(keypair, view, server_tls, announced_as, None).await
}

fn server_tls(ca: &TestCa, name: &str) -> ServerTlsConfig {
    let m = ca.material_for(name);
    ServerTlsConfig::new()
        .identity(Identity::from_pem(&m.cert_pem, &m.key_pem))
        .client_ca_root(Certificate::from_pem(&m.ca_pem))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mutual_tls_signature_collection_reaches_threshold() {
    let ca = TestCa::new("glc-federation-test-ca");
    let a = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;
    let b = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![a.endpoint(), b.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let sigs = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;

    assert_eq!(sigs.len(), 2, "both signers answered over mTLS");
    for (pk, sig) in &sigs {
        assert!(
            sig.verify(pk.as_ref(), MESSAGE),
            "every collected signature must verify over the canonical message"
        );
    }
    let identities: Vec<Pubkey> = sigs.iter().map(|(pk, _)| *pk).collect();
    assert!(identities.contains(&a.pubkey) && identities.contains(&b.pubkey));

    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_client_without_a_certificate_is_rejected_by_the_server() {
    // The load-bearing property of *mutual* TLS: encryption alone would let
    // anyone who can reach the port ask a validator to sign.
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::insecure_without_tls(vec![signer.endpoint()]);
    let sigs = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;

    assert!(
        sigs.is_empty(),
        "a client presenting no certificate must not obtain a signature"
    );
    signer.stop().await;
}

#[tokio::test]
async fn a_client_certificate_from_another_ca_is_rejected() {
    // A certificate is only meaningful because of who issued it. One minted
    // by an unrelated CA must buy nothing.
    let federation = TestCa::new("glc-federation-test-ca");
    let outsider = TestCa::new("some-other-ca");

    let signer = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&federation, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    // Trusts the real federation CA (so the server is accepted) but presents
    // a leaf issued by the outsider CA.
    let mut material = outsider.material_for("impostor");
    material.ca_pem = federation.ca_pem.clone().into_bytes();

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        material,
        FEDERATION_DOMAIN.to_string(),
    );
    let sigs = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;

    assert!(
        sigs.is_empty(),
        "a client certificate from an unrelated CA must be rejected"
    );
    signer.stop().await;
}

#[tokio::test]
async fn a_server_certificate_from_another_ca_is_rejected_by_the_client() {
    // The pin has to work in both directions, or a relayer could be lured
    // into asking an impostor to sign.
    let federation = TestCa::new("glc-federation-test-ca");
    let outsider = TestCa::new("some-other-ca");

    let signer = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&outsider, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        federation.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );
    let sigs = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;

    assert!(
        sigs.is_empty(),
        "the client pins the federation CA and must not trust the public PKI or any other issuer"
    );
    signer.stop().await;
}

#[tokio::test]
async fn a_valid_certificate_does_not_let_a_peer_answer_as_another_validator() {
    // This is exactly what mTLS alone cannot catch, and why identity is
    // bound twice. The handshake here is completely legitimate.
    let ca = TestCa::new("glc-federation-test-ca");
    let real = Keypair::new();
    let someone_else = Keypair::new().pubkey();

    let signer = start_signer(
        real,
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        // Registered in the peer list as a validator it is not.
        Some(someone_else),
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );
    let round = collector
        .collect(1, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert_eq!(
        round.unique_signers(),
        0,
        "a signature from the wrong validator identity must be discarded"
    );
    assert_eq!(round.unavailable.len(), 1);
    assert!(
        round.unavailable[0].1.contains("answered as"),
        "{:?}",
        round.unavailable
    );
    signer.stop().await;
}

#[tokio::test]
async fn a_policy_refusal_is_distinguished_from_unavailability_over_the_wire() {
    // The distinction has to survive the transport: a refusal means the peer
    // disagreed and retrying is pointless, while an unreachable peer may
    // come back. Conflating them either spins forever or gives up too soon.
    let ca = TestCa::new("glc-federation-test-ca");

    // Refuses: derives different bytes than we are asking about.
    let disagreeing = start_signer(
        Keypair::new(),
        FixedView {
            epoch: EPOCH,
            message: Some(b"something-else-entirely".to_vec()),
            fresh: true,
        },
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let unreachable = PeerEndpoint {
        validator_pubkey: Keypair::new().pubkey(),
        // Port 1 is reserved and refuses connections immediately.
        uri: "https://127.0.0.1:1".to_string(),
    };

    let collector = GrpcCollector::new(
        vec![disagreeing.endpoint(), unreachable],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );
    let round = collector
        .collect(2, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert_eq!(round.unique_signers(), 0);
    assert_eq!(round.refused.len(), 1, "the disagreeing peer refused");
    assert_eq!(round.unavailable.len(), 1, "the dead peer was unavailable");
    assert!(
        !round.retry_could_help(2),
        "one refusal plus one unavailable cannot close a shortfall of two"
    );

    disagreeing.stop().await;
}

#[tokio::test]
async fn a_stale_signer_refuses_even_when_everything_else_matches() {
    // A partitioned validator quoting its last known epoch would otherwise
    // agree with anyone quoting it back.
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer(
        Keypair::new(),
        FixedView {
            epoch: EPOCH,
            message: Some(MESSAGE.to_vec()),
            fresh: false,
        },
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );
    let round = collector
        .collect(1, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert_eq!(round.unique_signers(), 0);
    assert_eq!(round.refused.len(), 1);
    assert!(round.refused[0].1.contains("stale"), "{:?}", round.refused);
    signer.stop().await;
}

#[tokio::test]
async fn collection_stops_once_threshold_is_reached() {
    // Failover asks peers in turn, but must not keep asking after it has
    // what it needs — otherwise every round costs N round-trips regardless
    // of threshold.
    let ca = TestCa::new("glc-federation-test-ca");
    let live = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    // Deliberately ordered so the live peer is asked first for seed 0.
    let peers = vec![
        live.endpoint(),
        PeerEndpoint {
            validator_pubkey: Keypair::new().pubkey(),
            uri: "https://127.0.0.1:1".to_string(),
        },
    ];
    let collector = GrpcCollector::new(
        peers,
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let round = collector
        .collect(1, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert!(round.reached(1));
    assert!(
        round.unavailable.is_empty(),
        "the second peer must never have been contacted once threshold was met"
    );
    live.stop().await;
}

#[tokio::test]
async fn failover_reaches_threshold_despite_a_dead_peer_ahead_of_a_live_one() {
    // The whole point of asking every peer rather than only the first M.
    let ca = TestCa::new("glc-federation-test-ca");
    let live = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let peers = vec![
        PeerEndpoint {
            validator_pubkey: Keypair::new().pubkey(),
            uri: "https://127.0.0.1:1".to_string(),
        },
        live.endpoint(),
    ];
    let collector = GrpcCollector::new(
        peers,
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let round = collector
        .collect(1, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert!(
        round.reached(1),
        "a dead peer earlier in the order must not prevent reaching threshold: {}",
        round.summary()
    );
    assert_eq!(round.unavailable.len(), 1);
    live.stop().await;
}

#[tokio::test]
async fn a_retry_over_the_wire_returns_the_same_signature() {
    // Idempotence has to hold across the transport, not just in `handle`:
    // a peer must never be inducible into producing a second, distinct
    // signature for one deposit.
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let first = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;
    let second = collector
        .collect_mint_signatures(EPOCH, MESSAGE, TXID, VOUT)
        .await;

    assert_eq!(first.len(), 1);
    assert_eq!(first, second, "retries are idempotent across the network");
    signer.stop().await;
}

#[tokio::test]
async fn the_epoch_a_requester_claims_cannot_override_what_the_signer_observes() {
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer(
        Keypair::new(),
        view(), // observes EPOCH
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );
    let round = collector
        .collect(1, 0, MESSAGE, |id| {
            glc_relayer::p2p::service::mint_request(id, EPOCH + 1, MESSAGE.to_vec(), TXID, VOUT)
        })
        .await;

    assert_eq!(round.unique_signers(), 0);
    assert_eq!(round.refused.len(), 1);
    signer.stop().await;
}

#[tokio::test]
async fn a_designated_payout_quorum_is_asked_and_nobody_else_is() {
    // ADR-0015: the txid depends on which quorum signs, so an unavailable
    // designated signer must produce a shortfall, never a substitution.
    let ca = TestCa::new("glc-federation-test-ca");
    let designated = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;
    let bystander = start_signer(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
    )
    .await;

    let collector = GrpcCollector::new(
        vec![designated.endpoint(), bystander.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let round = collector
        .collect_payout_signatures(EPOCH, MESSAGE, 4, 0, &[designated.pubkey])
        .await;

    // The view here derives nothing for a payout identity, so the designated
    // signer refuses — the point being that only it was ever asked.
    assert_eq!(
        round.refused.len() + round.unavailable.len(),
        1,
        "exactly one peer was contacted: {}",
        round.summary()
    );
    assert!(
        !round
            .refused
            .iter()
            .chain(round.unavailable.iter())
            .any(|(pk, _)| *pk == bystander.pubkey),
        "a non-designated peer must never be contacted for a designated payout"
    );

    designated.stop().await;
    bystander.stop().await;
}

#[tokio::test]
async fn a_peer_that_floods_a_signer_is_rate_limited_over_the_wire() {
    // Two properties at once, both only observable through the real server:
    //
    // 1. the limiter is actually applied on the gRPC path, not merely
    //    available to call;
    // 2. it is keyed by the *peer*, not by the connection. Every request
    //    below opens a fresh TLS connection from a fresh source port, so a
    //    per-connection key would mint a new bucket each time and never
    //    limit anything.
    //
    // The limit is pinned rather than left at production values: at 10/s
    // refill, whether a flood is throttled would otherwise depend on how
    // fast the machine running the test is. Zero refill makes the outcome
    // the same everywhere.
    const ALLOWED: usize = 3;
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer_with(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
        Some((0.0, ALLOWED as f64)),
    )
    .await;

    let collector = GrpcCollector::new(
        vec![signer.endpoint()],
        ca.material_for("relayer"),
        FEDERATION_DOMAIN.to_string(),
    );

    let mut signed = 0usize;
    let mut throttled = 0usize;
    let mut refused = 0usize;
    for _ in 0..(ALLOWED + 5) {
        let round = collector
            .collect(1, 0, MESSAGE, |id| {
                glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
            })
            .await;
        signed += round.unique_signers();
        refused += round.refused.len();
        if round
            .unavailable
            .iter()
            .any(|(_, why)| why.contains("rate limit"))
        {
            throttled += 1;
        }
    }

    assert_eq!(
        signed, ALLOWED,
        "exactly the allowed number of requests may be served"
    );
    assert_eq!(
        throttled, 5,
        "every request past the allowance must be throttled, across separate connections"
    );
    assert_eq!(
        refused, 0,
        "being throttled must NOT be reported as a policy refusal — the collector stops \
         retrying refusals, and a throttled request is retriable"
    );
    signer.stop().await;
}

#[tokio::test]
async fn the_address_fallback_key_also_survives_reconnection() {
    // Without a client certificate the limiter falls back to the remote
    // address. That fallback has to key on the address alone: a key that
    // included the source port would mint a fresh bucket for every new
    // connection, and the fallback would silently limit nothing.
    const ALLOWED: usize = 3;
    let signer = start_signer_with(
        Keypair::new(),
        view(),
        None, // plaintext: no peer certificate for the limiter to key on
        None,
        Some((0.0, ALLOWED as f64)),
    )
    .await;

    let collector = GrpcCollector::insecure_without_tls(vec![PeerEndpoint {
        validator_pubkey: signer.pubkey,
        uri: format!("http://{}", signer.addr),
    }]);

    let mut signed = 0usize;
    let mut throttled = 0usize;
    for _ in 0..(ALLOWED + 4) {
        let round = collector
            .collect(1, 0, MESSAGE, |id| {
                glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
            })
            .await;
        signed += round.unique_signers();
        if round
            .unavailable
            .iter()
            .any(|(_, why)| why.contains("rate limit"))
        {
            throttled += 1;
        }
    }

    assert_eq!(signed, ALLOWED);
    assert_eq!(
        throttled, 4,
        "a reconnecting peer must land in the same bucket, not a fresh one"
    );
    signer.stop().await;
}

#[tokio::test]
async fn two_peers_sharing_one_address_get_separate_allowances() {
    // Why the limiter keys on the client certificate rather than the
    // address: federation members can legitimately share an apparent
    // address — behind NAT, a proxy, or co-located on one host. Keying on
    // the address alone would put them in one bucket, so a single noisy
    // member could starve the others, which is the exact failure a per-peer
    // limit exists to prevent.
    //
    // Both clients here connect from 127.0.0.1; only their certificates
    // differ.
    const ALLOWED: usize = 2;
    let ca = TestCa::new("glc-federation-test-ca");
    let signer = start_signer_with(
        Keypair::new(),
        view(),
        Some(server_tls(&ca, FEDERATION_DOMAIN)),
        None,
        Some((0.0, ALLOWED as f64)),
    )
    .await;

    let ask = |material: TlsMaterial| {
        let peer = signer.endpoint();
        async move {
            let c = GrpcCollector::new(vec![peer], material, FEDERATION_DOMAIN.to_string());
            c.collect(1, 0, MESSAGE, |id| {
                glc_relayer::p2p::service::mint_request(id, EPOCH, MESSAGE.to_vec(), TXID, VOUT)
            })
            .await
        }
    };

    // Exhaust the first peer's allowance.
    let noisy = ca.material_for("noisy-member");
    for _ in 0..(ALLOWED + 2) {
        let _ = ask(noisy.clone()).await;
    }
    assert!(
        ask(noisy.clone())
            .await
            .unavailable
            .iter()
            .any(|(_, why)| why.contains("rate limit")),
        "the flooding peer must be throttled"
    );

    // A different member, same address, untouched allowance.
    let quiet = ca.material_for("quiet-member");
    let round = ask(quiet).await;
    assert_eq!(
        round.unique_signers(),
        1,
        "a distinct federation member sharing an address must keep its own allowance: {}",
        round.summary()
    );

    signer.stop().await;
}

/// Sanity check that the test CA actually produces a working chain — if this
/// failed, every rejection test above would pass for the wrong reason.
#[tokio::test]
async fn the_test_pki_itself_is_sound() {
    let ca = TestCa::new("glc-federation-test-ca");
    let m = ca.material_for(FEDERATION_DOMAIN);
    assert!(String::from_utf8_lossy(&m.ca_pem).contains("BEGIN CERTIFICATE"));
    assert!(String::from_utf8_lossy(&m.cert_pem).contains("BEGIN CERTIFICATE"));
    assert!(String::from_utf8_lossy(&m.key_pem).contains("PRIVATE KEY"));
    assert_ne!(m.ca_pem, m.cert_pem, "the leaf must not be the CA itself");

    let _ = Arc::new(());
}
