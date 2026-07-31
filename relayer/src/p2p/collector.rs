//! Peer signature collection over mTLS gRPC (Phase 7c/7d, ADR-0016).
//!
//! Implements [`SignatureCollector`] by asking federation peers, over
//! mutually-authenticated TLS, for signatures over a canonical message.
//!
//! # What this layer decides, and what it does not
//!
//! It decides *who to ask*, *how long to wait*, and *when a round is done*
//! ([`super::aggregation`]). It does not decide what should be signed: peers
//! independently re-derive every message and sign only what they derived
//! ([`super::policy`]). Only signatures cross the network.
//!
//! # Every response is checked twice
//!
//! mTLS proves the peer holds a certificate issued by the federation's own
//! CA. That is not sufficient on its own, so each response is additionally
//! checked against the **on-chain ed25519 identity** the endpoint is
//! registered as, and its signature must verify over the message actually
//! requested. A stolen certificate therefore cannot impersonate a validator,
//! and a peer cannot contribute another member's signature, nor one over
//! different bytes.
//!
//! # Falling short is normal; a refusal is not
//!
//! Missing threshold is an ordinary tick outcome the orchestrator retries
//! later, never an error that strands a deposit. A *refusal*, though, means
//! that peer independently disagreed about what should be signed — an alarm,
//! and not something a retry will fix.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::orchestrator::SignatureCollector;
use crate::p2p::aggregation::{ask_order, PeerOutcome, Round, PER_PEER_TIMEOUT, ROUND_TIMEOUT};
use crate::p2p::identity::{PeerEndpoint, TlsMaterial};
use crate::p2p::service::pb::federation_signer_client::FederationSignerClient;
use crate::p2p::service::{mint_request, payout_request, pb};

pub struct GrpcCollector {
    peers: Vec<PeerEndpoint>,
    /// `None` means no transport authentication at all — see
    /// [`GrpcCollector::insecure_without_tls`].
    tls: Option<TlsMaterial>,
    /// The name peer certificates must be issued for. Pinned by
    /// configuration rather than taken from the URI, so a peer cannot
    /// present a certificate for a name it merely happens to control.
    tls_domain: String,
}

impl GrpcCollector {
    /// Production constructor: mutual TLS against the federation's own CA.
    pub fn new(peers: Vec<PeerEndpoint>, tls: TlsMaterial, tls_domain: String) -> Self {
        GrpcCollector {
            peers,
            tls: Some(tls),
            tls_domain,
        }
    }

    /// Plaintext transport, for loopback and tests.
    ///
    /// Deliberately named so its use is conspicuous in review and in
    /// configuration: a deployment reaching for this has no transport
    /// authentication whatsoever, and rests entirely on the application-layer
    /// identity check in [`GrpcCollector::accept`].
    pub fn insecure_without_tls(peers: Vec<PeerEndpoint>) -> Self {
        GrpcCollector {
            peers,
            tls: None,
            tls_domain: String::new(),
        }
    }

    fn next_request_id() -> Vec<u8> {
        // Unique per request so a retry is distinguishable from a fresh ask.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.to_le_bytes().to_vec()
    }

    async fn connect(&self, uri: &str) -> Result<FederationSignerClient<Channel>, String> {
        let mut endpoint = Channel::from_shared(uri.to_string())
            .map_err(|e| format!("bad peer uri: {e}"))?
            .connect_timeout(PER_PEER_TIMEOUT)
            .timeout(PER_PEER_TIMEOUT);

        if let Some(tls) = &self.tls {
            let cfg = ClientTlsConfig::new()
                // Pin the federation CA. The public web PKI is deliberately
                // NOT trusted here: otherwise any publicly-issued
                // certificate for a matching name would be accepted.
                .ca_certificate(Certificate::from_pem(tls.ca_pem.clone()))
                .domain_name(self.tls_domain.clone())
                // Present our own certificate, so the peer authenticates us
                // exactly as we authenticate it.
                .identity(Identity::from_pem(
                    tls.cert_pem.clone(),
                    tls.key_pem.clone(),
                ));
            endpoint = endpoint
                .tls_config(cfg)
                .map_err(|e| format!("tls configuration rejected: {e}"))?;
        }

        endpoint
            .connect()
            .await
            .map(FederationSignerClient::new)
            .map_err(|e| format!("connect failed: {e}"))
    }

    /// Accepts a response only if it is internally consistent.
    ///
    /// Both checks matter and neither implies the other: the identity check
    /// stops a peer answering as somebody else, the signature check stops it
    /// contributing a signature over bytes other than the ones we asked
    /// about.
    fn accept(
        expected: &Pubkey,
        message: &[u8],
        resp: pb::SignResponse,
    ) -> Result<(Pubkey, Signature), String> {
        let pubkey = Pubkey::try_from(resp.validator_pubkey.as_slice())
            .map_err(|_| "response carried a malformed validator pubkey".to_string())?;
        if pubkey != *expected {
            return Err(format!(
                "endpoint registered as {expected} answered as {pubkey}"
            ));
        }
        let sig = Signature::try_from(resp.signature.as_slice())
            .map_err(|_| "response carried a malformed signature".to_string())?;
        if !sig.verify(pubkey.as_ref(), message) {
            return Err("signature does not verify over the requested message".to_string());
        }
        Ok((pubkey, sig))
    }

    /// Asks one peer, bounded by [`PER_PEER_TIMEOUT`] at both connect and
    /// call, so one unresponsive peer cannot stall the round.
    async fn ask(&self, peer: &PeerEndpoint, req: pb::SignRequest, message: &[u8]) -> PeerOutcome {
        let mut client = match self.connect(&peer.uri).await {
            Ok(c) => c,
            Err(e) => return PeerOutcome::Unavailable(e),
        };
        match tokio::time::timeout(PER_PEER_TIMEOUT, client.sign(req)).await {
            Err(_) => PeerOutcome::Unavailable("per-peer timeout".to_string()),
            Ok(Err(status)) => {
                // `failed_precondition` is what `SignerService` returns for a
                // policy refusal. Kept distinct from unavailability because a
                // retry will get the same answer.
                if status.code() == tonic::Code::FailedPrecondition {
                    PeerOutcome::Refused(status.message().to_string())
                } else {
                    PeerOutcome::Unavailable(status.to_string())
                }
            }
            Ok(Ok(resp)) => {
                match Self::accept(&peer.validator_pubkey, message, resp.into_inner()) {
                    Ok((_, sig)) => PeerOutcome::Signed(sig),
                    // An inconsistent response counts as unavailability rather
                    // than refusal: the peer did not decline, it answered
                    // wrongly — a bug or an attack, but not a disagreement about
                    // what should be signed.
                    Err(why) => PeerOutcome::Unavailable(why),
                }
            }
        }
    }

    /// Runs one collection round, stopping as soon as `threshold` distinct
    /// signatures are in hand.
    ///
    /// Bounded by [`ROUND_TIMEOUT`] overall as well as per peer, so a
    /// pathological set of slow peers cannot stall a tick indefinitely.
    pub async fn collect(
        &self,
        threshold: usize,
        seed: u64,
        message: &[u8],
        build: impl Fn(Vec<u8>) -> pb::SignRequest,
    ) -> Round {
        let identities: Vec<Pubkey> = self.peers.iter().map(|p| p.validator_pubkey).collect();
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;

        for pubkey in ask_order(&identities, seed) {
            if round.reached(threshold) {
                break;
            }
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == pubkey) else {
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let outcome = self
                .ask(peer, build(Self::next_request_id()), message)
                .await;
            if let PeerOutcome::Refused(why) = &outcome {
                tracing::warn!(
                    peer = %pubkey,
                    reason = %why,
                    "peer refused to sign — its view of the chain disagrees with ours"
                );
            }
            round.record(pubkey, outcome);
        }
        round
    }

    /// Collects payout signatures from an **explicitly designated** quorum.
    ///
    /// Only the designated members are asked, and the request carries the
    /// `quorum_attempt`, so ADR-0015's determinism survives: falling short
    /// here must lead to an explicit, audited quorum reassignment, never an
    /// implicit substitution of some other available signer — the txid
    /// depends on which quorum signs.
    pub async fn collect_payout_signatures(
        &self,
        epoch: u64,
        message: &[u8],
        withdrawal_index: u64,
        quorum_attempt: u32,
        designated: &[Pubkey],
    ) -> Round {
        let mut round = Round::new();
        let deadline = tokio::time::Instant::now() + ROUND_TIMEOUT;
        for pubkey in designated {
            let Some(peer) = self.peers.iter().find(|p| p.validator_pubkey == *pubkey) else {
                round.record(
                    *pubkey,
                    PeerOutcome::Unavailable(
                        "designated signer is not a configured peer".to_string(),
                    ),
                );
                continue;
            };
            if tokio::time::Instant::now() >= deadline {
                round.record(
                    *pubkey,
                    PeerOutcome::Unavailable("round timeout".to_string()),
                );
                continue;
            }
            let req = payout_request(
                Self::next_request_id(),
                epoch,
                message.to_vec(),
                withdrawal_index,
                quorum_attempt,
            );
            let outcome = self.ask(peer, req, message).await;
            if let PeerOutcome::Refused(why) = &outcome {
                tracing::warn!(
                    peer = %pubkey,
                    withdrawal_index,
                    quorum_attempt,
                    reason = %why,
                    "designated payout signer refused"
                );
            }
            round.record(*pubkey, outcome);
        }
        tracing::info!(
            withdrawal_index,
            quorum_attempt,
            summary = %round.summary(),
            "payout signature collection round"
        );
        round
    }
}

impl SignatureCollector for GrpcCollector {
    async fn collect_mint_signatures(
        &self,
        epoch: u64,
        message: &[u8],
        txid: [u8; 32],
        vout: u32,
    ) -> Vec<(Pubkey, Signature)> {
        // Ask everyone rather than caching a threshold here: the on-chain
        // ValidatorSet is the authority on threshold, and the orchestrator
        // re-reads it before aggregating. A threshold cached at this layer
        // could go stale across a rotation and silently under-collect.
        let threshold = self.peers.len();
        let seed = u64::from_le_bytes(txid[..8].try_into().unwrap_or([0u8; 8])) ^ u64::from(vout);
        let msg = message.to_vec();
        let round = self
            .collect(threshold, seed, message, move |id| {
                mint_request(id, epoch, msg.clone(), txid, vout)
            })
            .await;
        tracing::info!(summary = %round.summary(), "mint signature collection round");
        round.signatures
    }
}

/// ⚠️ **TEST-ONLY.** Signs in-process with locally held keys.
///
/// This deliberately reintroduces the very property Phase 7c exists to
/// remove — one process holding several validator identities — so that
/// end-to-end tests can reach threshold without standing up N signer
/// processes and a network between them.
///
/// It must never be constructed by a deployed relayer. Production wiring
/// (`main.rs`) uses [`GrpcCollector`] exclusively, and the orchestrator
/// itself has no key parameter at all, so reaching for this in production
/// would be a deliberate act rather than an accident.
pub struct InProcessCollector {
    keys: Vec<solana_sdk::signature::Keypair>,
}

impl InProcessCollector {
    pub fn new(keys: Vec<solana_sdk::signature::Keypair>) -> Self {
        InProcessCollector { keys }
    }
}

impl SignatureCollector for InProcessCollector {
    async fn collect_mint_signatures(
        &self,
        _epoch: u64,
        message: &[u8],
        _txid: [u8; 32],
        _vout: u32,
    ) -> Vec<(Pubkey, Signature)> {
        use solana_sdk::signature::Signer;
        self.keys
            .iter()
            .map(|k| (k.pubkey(), k.sign_message(message)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};
    use std::time::Duration;

    fn resp(kp: &Keypair, message: &[u8]) -> pb::SignResponse {
        pb::SignResponse {
            request_id: vec![1],
            validator_pubkey: kp.pubkey().to_bytes().to_vec(),
            signature: kp.sign_message(message).as_ref().to_vec(),
        }
    }

    /// An endpoint whose port refuses connections immediately.
    fn dead_peer(port: u16) -> PeerEndpoint {
        PeerEndpoint {
            validator_pubkey: Keypair::new().pubkey(),
            uri: format!("http://127.0.0.1:{port}"),
        }
    }

    #[test]
    fn accepts_a_correct_response() {
        let kp = Keypair::new();
        let msg = b"canonical";
        assert!(GrpcCollector::accept(&kp.pubkey(), msg, resp(&kp, msg)).is_ok());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let kp = Keypair::new();
        // Correctly signed by the right validator, but over other bytes.
        let err = GrpcCollector::accept(&kp.pubkey(), b"canonical", resp(&kp, b"other"))
            .expect_err("a signature must verify over the message we actually asked about");
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn rejects_a_response_claiming_another_validators_identity() {
        // mTLS alone cannot catch this: a peer holding a valid federation
        // certificate must still not be able to answer as somebody else.
        let kp = Keypair::new();
        let impostor = Keypair::new();
        let msg = b"canonical";
        let err = GrpcCollector::accept(&impostor.pubkey(), msg, resp(&kp, msg))
            .expect_err("a peer must not contribute another validator's signature");
        assert!(err.contains("answered as"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_signature_or_pubkey() {
        let kp = Keypair::new();
        let mut r = resp(&kp, b"canonical");
        r.signature = vec![0u8; 10];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r).is_err());

        let mut r2 = resp(&kp, b"canonical");
        r2.validator_pubkey = vec![0u8; 5];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r2).is_err());
    }

    #[test]
    fn request_ids_are_unique_across_calls() {
        let a = GrpcCollector::next_request_id();
        std::thread::sleep(Duration::from_nanos(1));
        let b = GrpcCollector::next_request_id();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn an_unreachable_peer_is_bounded_and_classified_unavailable() {
        // The point is not that it fails, but that it fails *promptly* and
        // as unavailability rather than refusal — only unavailability
        // justifies a retry.
        let peer = dead_peer(1);
        let c = GrpcCollector::insecure_without_tls(vec![peer.clone()]);
        let started = std::time::Instant::now();
        let outcome = c
            .ask(
                &peer,
                mint_request(vec![1], 0, b"m".to_vec(), [0u8; 32], 0),
                b"m",
            )
            .await;
        assert!(
            matches!(outcome, PeerOutcome::Unavailable(_)),
            "got {outcome:?}"
        );
        assert!(
            started.elapsed() < PER_PEER_TIMEOUT + Duration::from_secs(2),
            "an unreachable peer must be bounded by the per-peer timeout"
        );
    }

    #[tokio::test]
    async fn a_round_of_unreachable_peers_completes_and_reports_a_retriable_shortfall() {
        let c = GrpcCollector::insecure_without_tls(vec![dead_peer(1), dead_peer(2)]);
        let round = c
            .collect(2, 0, b"m", |id| {
                mint_request(id, 0, b"m".to_vec(), [0u8; 32], 0)
            })
            .await;
        assert_eq!(round.unique_signers(), 0);
        assert_eq!(round.unavailable.len(), 2, "both peers were tried");
        assert!(!round.reached(2));
        assert!(
            round.retry_could_help(2),
            "unreachable peers may come back, so a later tick should try again"
        );
    }

    #[tokio::test]
    async fn a_designated_payout_signer_that_is_not_a_configured_peer_is_a_shortfall() {
        // ADR-0015 forbids substituting a different signer, because the txid
        // depends on which quorum signs. This must surface as a shortfall,
        // never be quietly filled from the available peers.
        let stranger = Keypair::new().pubkey();
        let c = GrpcCollector::insecure_without_tls(vec![dead_peer(1)]);
        let round = c
            .collect_payout_signatures(0, b"m", 4, 0, &[stranger])
            .await;
        assert_eq!(round.unique_signers(), 0);
        assert_eq!(round.unavailable.len(), 1);
        assert!(
            round.unavailable[0].1.contains("not a configured peer"),
            "{:?}",
            round.unavailable
        );
        assert_eq!(
            round.unavailable[0].0, stranger,
            "the shortfall is attributed to the designated signer"
        );
    }

    #[tokio::test]
    async fn payout_collection_asks_only_the_designated_quorum() {
        // A non-designated peer must not be asked at all, even when it is
        // configured and the designated one is down.
        let designated = dead_peer(1);
        let other = dead_peer(2);
        let c = GrpcCollector::insecure_without_tls(vec![designated.clone(), other.clone()]);
        let round = c
            .collect_payout_signatures(0, b"m", 4, 0, &[designated.validator_pubkey])
            .await;
        assert_eq!(round.unavailable.len(), 1, "only the designated peer");
        assert_eq!(round.unavailable[0].0, designated.validator_pubkey);
        assert!(
            !round
                .unavailable
                .iter()
                .any(|(pk, _)| *pk == other.validator_pubkey),
            "a non-designated peer must never be substituted in"
        );
    }
}
