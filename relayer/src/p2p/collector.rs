//! Peer signature collection over gRPC (Phase 7c, ADR-0016).
//!
//! Implements [`SignatureCollector`] by asking each configured federation
//! peer for a signature. Peers that refuse or are unreachable simply do not
//! contribute: falling short of threshold is a normal outcome that the
//! orchestrator retries on a later tick, never an error that strands a
//! deposit.
//!
//! Every returned signature is **verified against the message before being
//! accepted**, and against the pubkey the peer claims. A peer cannot
//! contribute a signature by another validator, nor one over different
//! bytes.

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

use crate::orchestrator::SignatureCollector;
use crate::p2p::service::pb::federation_signer_client::FederationSignerClient;
use crate::p2p::service::{mint_request, pb};

/// One federation peer's endpoint.
#[derive(Debug, Clone)]
pub struct PeerEndpoint {
    /// The validator identity this endpoint is expected to answer as.
    /// Checked against the response; a mismatch is discarded.
    pub validator_pubkey: Pubkey,
    pub uri: String,
}

pub struct GrpcCollector {
    peers: Vec<PeerEndpoint>,
}

impl GrpcCollector {
    pub fn new(peers: Vec<PeerEndpoint>) -> Self {
        GrpcCollector { peers }
    }

    fn next_request_id() -> Vec<u8> {
        // Unique per request so a retry is distinguishable from a fresh ask.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        nanos.to_le_bytes().to_vec()
    }

    /// Accepts a response only if it is internally consistent: the claimed
    /// identity is the one this endpoint is registered as, and the
    /// signature actually verifies over the message we asked about.
    fn accept(
        expected: &Pubkey,
        message: &[u8],
        resp: pb::SignResponse,
    ) -> Option<(Pubkey, Signature)> {
        let pubkey = Pubkey::try_from(resp.validator_pubkey.as_slice()).ok()?;
        if pubkey != *expected {
            tracing::warn!(%pubkey, expected = %expected, "peer answered as a different validator");
            return None;
        }
        let sig = Signature::try_from(resp.signature.as_slice()).ok()?;
        if !sig.verify(pubkey.as_ref(), message) {
            tracing::warn!(%pubkey, "peer returned a signature that does not verify");
            return None;
        }
        Some((pubkey, sig))
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
        let mut out = Vec::with_capacity(self.peers.len());
        for peer in &self.peers {
            let req = mint_request(Self::next_request_id(), epoch, message.to_vec(), txid, vout);
            match FederationSignerClient::connect(peer.uri.clone()).await {
                Ok(mut client) => match client.sign(req).await {
                    Ok(resp) => {
                        if let Some(pair) =
                            Self::accept(&peer.validator_pubkey, message, resp.into_inner())
                        {
                            out.push(pair);
                        }
                    }
                    Err(status) => {
                        // A refusal means that peer's view of the chain
                        // disagrees with ours — an alarm, not routine.
                        tracing::warn!(
                            peer = %peer.validator_pubkey,
                            status = %status,
                            "peer refused or failed a signing request"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(peer = %peer.validator_pubkey, error = %e, "peer unreachable")
                }
            }
        }
        out
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

    fn resp(kp: &Keypair, message: &[u8]) -> pb::SignResponse {
        pb::SignResponse {
            request_id: vec![1],
            validator_pubkey: kp.pubkey().to_bytes().to_vec(),
            signature: kp.sign_message(message).as_ref().to_vec(),
        }
    }

    #[test]
    fn accepts_a_correct_response() {
        let kp = Keypair::new();
        let msg = b"canonical";
        assert!(GrpcCollector::accept(&kp.pubkey(), msg, resp(&kp, msg)).is_some());
    }

    #[test]
    fn rejects_a_signature_over_different_bytes() {
        let kp = Keypair::new();
        // Signed something else entirely.
        let r = resp(&kp, b"other");
        assert!(
            GrpcCollector::accept(&kp.pubkey(), b"canonical", r).is_none(),
            "a signature must verify over the message we actually asked about"
        );
    }

    #[test]
    fn rejects_a_response_claiming_another_validators_identity() {
        let kp = Keypair::new();
        let impostor = Keypair::new();
        let msg = b"canonical";
        // Correctly signed by `kp`, but this endpoint is registered as
        // `impostor` — a peer must not contribute another validator's
        // signature.
        assert!(GrpcCollector::accept(&impostor.pubkey(), msg, resp(&kp, msg)).is_none());
    }

    #[test]
    fn rejects_a_malformed_signature_or_pubkey() {
        let kp = Keypair::new();
        let mut r = resp(&kp, b"canonical");
        r.signature = vec![0u8; 10];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r).is_none());

        let mut r2 = resp(&kp, b"canonical");
        r2.validator_pubkey = vec![0u8; 5];
        assert!(GrpcCollector::accept(&kp.pubkey(), b"canonical", r2).is_none());
    }

    #[test]
    fn request_ids_are_unique_across_calls() {
        let a = GrpcCollector::next_request_id();
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let b = GrpcCollector::next_request_id();
        assert_ne!(a, b);
    }
}
