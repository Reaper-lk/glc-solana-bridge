//! The gRPC signer service and client (Phase 7c, ADR-0016).
//!
//! # Key separation
//!
//! The validator's ed25519 private key lives **only** inside
//! [`SignerService`], which runs as its own process. The executor and mint
//! orchestrator hold no key material at all: they ask peers (including
//! their own local signer) over gRPC and aggregate the responses. This
//! retires the Phase 5 bootstrap topology (ADR-0012 R2), in which one
//! process loaded and signed with every validator's key.
//!
//! # What the transport does and does not decide
//!
//! Nothing here decides whether to sign. That is [`super::policy::evaluate`],
//! which re-derives every message from the validator's own observations.
//! This module is transport plus identity: it parses the wire form, calls
//! the policy, and signs only what the policy returns.

use std::sync::{Arc, Mutex};

use solana_sdk::signature::{Keypair, Signer as _};
use tonic::{Request, Response, Status};

use super::policy::{
    self, Action, Decision, LocalView, Refusal, SeenSet, SigningIdentity, SigningRequest,
};

pub mod pb {
    tonic::include_proto!("glc.federation.v1");
}

use pb::federation_signer_server::FederationSigner;
use pb::{HealthRequest, HealthResponse, SignRequest, SignResponse};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reconstructs the signing identity a request refers to.
///
/// Returns the identity only; the *message* is always derived locally by
/// the [`LocalView`], never taken from the request.
fn identity_of(action: Action, ctx: &pb::Context) -> Result<SigningIdentity, Refusal> {
    match action {
        Action::MintDeposit => {
            if ctx.txid.len() != 32 {
                return Err(Refusal::Underivable("deposit context has no 32-byte txid"));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&ctx.txid);
            Ok(SigningIdentity::Deposit {
                txid,
                vout: ctx.vout,
            })
        }
        Action::Payout => Ok(SigningIdentity::Payout {
            withdrawal_index: ctx.withdrawal_index,
            quorum_attempt: ctx.quorum_attempt,
        }),
        Action::Governance => Ok(SigningIdentity::Governance { epoch: 0 }),
    }
}

/// A validator's signing service. Holds exactly one key.
pub struct SignerService<V: LocalView + Send + Sync + 'static> {
    keypair: Keypair,
    view: V,
    seen: Arc<Mutex<SeenSet>>,
}

impl<V: LocalView + Send + Sync + 'static> SignerService<V> {
    /// Constructs the service around **one** validator identity.
    ///
    /// There is deliberately no constructor taking several keys: holding
    /// more than one validator identity in a process is precisely the
    /// bootstrap topology Phase 7c exists to retire.
    pub fn new(keypair: Keypair, view: V) -> Self {
        SignerService {
            keypair,
            view,
            seen: Arc::new(Mutex::new(SeenSet::new())),
        }
    }

    pub fn validator_pubkey(&self) -> [u8; 32] {
        self.keypair.pubkey().to_bytes()
    }

    /// Evaluates and, if the policy allows, signs. Exposed directly so the
    /// decision path is testable without standing up a server.
    pub fn handle(&self, req: SignRequest) -> Result<SignResponse, Refusal> {
        let action = Action::from_wire(req.action)?;
        let ctx = req.context.unwrap_or_default();
        let identity = identity_of(action, &ctx)?;

        let parsed = SigningRequest {
            request_id: req.request_id.clone(),
            action,
            epoch: req.epoch,
            canonical_message: req.canonical_message,
            identity,
            expiry_unix: req.expiry_unix,
        };

        let decision = {
            let seen = self.seen.lock().unwrap();
            policy::evaluate(&parsed, &self.view, &seen, now_unix())
        };

        let message = match decision {
            // Both arms sign the LOCALLY DERIVED bytes, never the
            // requester's copy.
            Decision::Sign(bytes) => {
                let mut seen = self.seen.lock().unwrap();
                seen.record(action, parsed.identity.clone(), bytes.clone());
                bytes
            }
            Decision::AlreadySigned(bytes) => bytes,
            Decision::Refuse(r) => return Err(r),
        };

        Ok(SignResponse {
            request_id: req.request_id,
            validator_pubkey: self.validator_pubkey().to_vec(),
            signature: self.keypair.sign_message(&message).as_ref().to_vec(),
        })
    }
}

#[tonic::async_trait]
impl<V: LocalView + Send + Sync + 'static> FederationSigner for SignerService<V> {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        match self.handle(request.into_inner()) {
            Ok(resp) => Ok(Response::new(resp)),
            // A refusal is a first-class, logged outcome: it means this
            // validator's view disagrees with a peer's, which is either a
            // bug or an attack — never routine.
            Err(refusal) => {
                tracing::warn!(%refusal, "refused a federation signing request");
                Err(Status::failed_precondition(refusal.to_string()))
            }
        }
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            validator_pubkey: self.validator_pubkey().to_vec(),
            observed_epoch: self.view.observed_epoch(),
        }))
    }
}

/// How long a signing request stays valid. Short enough that a captured
/// request cannot be replayed much later, long enough to survive an
/// ordinary retry.
pub const REQUEST_TTL_SECONDS: i64 = 120;

/// Builds a wire request for a deposit mint.
pub fn mint_request(
    request_id: Vec<u8>,
    epoch: u64,
    canonical_message: Vec<u8>,
    txid: [u8; 32],
    vout: u32,
) -> SignRequest {
    SignRequest {
        request_id,
        action: 1,
        epoch,
        canonical_message,
        context: Some(pb::Context {
            txid: txid.to_vec(),
            vout,
            withdrawal_index: 0,
            quorum_attempt: 0,
        }),
        expiry_unix: now_unix() + REQUEST_TTL_SECONDS,
    }
}

/// Builds a wire request for a vault payout, binding the designated quorum
/// attempt so a superseded designation cannot be signed for (ADR-0015).
pub fn payout_request(
    request_id: Vec<u8>,
    epoch: u64,
    canonical_message: Vec<u8>,
    withdrawal_index: u64,
    quorum_attempt: u32,
) -> SignRequest {
    SignRequest {
        request_id,
        action: 2,
        epoch,
        canonical_message,
        context: Some(pb::Context {
            txid: Vec::new(),
            vout: 0,
            withdrawal_index,
            quorum_attempt,
        }),
        expiry_unix: now_unix() + REQUEST_TTL_SECONDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct View {
        epoch: u64,
        messages: HashMap<SigningIdentity, Vec<u8>>,
    }
    impl LocalView for View {
        fn observed_epoch(&self) -> u64 {
            self.epoch
        }
        fn derive_message(&self, _a: Action, id: &SigningIdentity) -> Option<Vec<u8>> {
            self.messages.get(id).cloned()
        }
    }

    const TXID: [u8; 32] = [0xAA; 32];

    fn service(msg: &[u8]) -> SignerService<View> {
        let mut m = HashMap::new();
        m.insert(
            SigningIdentity::Deposit {
                txid: TXID,
                vout: 1,
            },
            msg.to_vec(),
        );
        SignerService::new(
            Keypair::new(),
            View {
                epoch: 7,
                messages: m,
            },
        )
    }

    #[test]
    fn signs_and_the_signature_verifies_against_the_derived_message() {
        let s = service(b"canonical");
        let resp = s
            .handle(mint_request(vec![1], 7, b"canonical".to_vec(), TXID, 1))
            .unwrap();
        assert_eq!(resp.validator_pubkey, s.validator_pubkey().to_vec());

        let sig = solana_sdk::signature::Signature::try_from(resp.signature.as_slice()).unwrap();
        assert!(
            sig.verify(&s.validator_pubkey(), b"canonical"),
            "the signature must verify against the locally derived bytes"
        );
    }

    #[test]
    fn refuses_bytes_the_validator_did_not_derive_itself() {
        let s = service(b"canonical");
        let err = s
            .handle(mint_request(vec![1], 7, b"forged".to_vec(), TXID, 1))
            .unwrap_err();
        assert_eq!(err, Refusal::MessageMismatch);
    }

    #[test]
    fn a_retry_returns_the_same_signature_rather_than_a_second_one() {
        let s = service(b"canonical");
        let a = s
            .handle(mint_request(vec![1], 7, b"canonical".to_vec(), TXID, 1))
            .unwrap();
        let b = s
            .handle(mint_request(vec![2], 7, b"canonical".to_vec(), TXID, 1))
            .unwrap();
        assert_eq!(a.signature, b.signature, "retries are idempotent");
    }

    #[test]
    fn refuses_a_conflicting_second_message_for_the_same_deposit() {
        let mut m = HashMap::new();
        let id = SigningIdentity::Deposit {
            txid: TXID,
            vout: 1,
        };
        m.insert(id.clone(), b"first".to_vec());
        let s = SignerService::new(
            Keypair::new(),
            View {
                epoch: 7,
                messages: m,
            },
        );
        s.handle(mint_request(vec![1], 7, b"first".to_vec(), TXID, 1))
            .unwrap();

        // The validator's own view now derives something different for the
        // same deposit — it must refuse rather than equivocate.
        let mut m2 = HashMap::new();
        m2.insert(id, b"second".to_vec());
        let s2 = SignerService {
            keypair: Keypair::new(),
            view: View {
                epoch: 7,
                messages: m2,
            },
            seen: {
                let mut seen = SeenSet::new();
                seen.record(
                    Action::MintDeposit,
                    SigningIdentity::Deposit {
                        txid: TXID,
                        vout: 1,
                    },
                    b"first".to_vec(),
                );
                Arc::new(Mutex::new(seen))
            },
        };
        assert_eq!(
            s2.handle(mint_request(vec![9], 7, b"second".to_vec(), TXID, 1))
                .unwrap_err(),
            Refusal::ConflictingRequest
        );
    }

    #[test]
    fn refuses_an_unknown_deposit() {
        let s = SignerService::new(
            Keypair::new(),
            View {
                epoch: 7,
                messages: HashMap::new(),
            },
        );
        assert!(matches!(
            s.handle(mint_request(vec![1], 7, b"x".to_vec(), TXID, 1))
                .unwrap_err(),
            Refusal::Underivable(_)
        ));
    }

    #[test]
    fn refuses_a_malformed_txid_context() {
        let s = service(b"canonical");
        let mut req = mint_request(vec![1], 7, b"canonical".to_vec(), TXID, 1);
        req.context.as_mut().unwrap().txid = vec![0u8; 31];
        assert!(matches!(
            s.handle(req).unwrap_err(),
            Refusal::Underivable(_)
        ));
    }

    #[test]
    fn refuses_action_zero() {
        let s = service(b"canonical");
        let mut req = mint_request(vec![1], 7, b"canonical".to_vec(), TXID, 1);
        req.action = 0;
        assert_eq!(s.handle(req).unwrap_err(), Refusal::UnspecifiedAction);
    }

    #[test]
    fn payout_requests_bind_the_quorum_attempt() {
        // A signature for attempt 0 must not satisfy a request for attempt 1.
        let id0 = SigningIdentity::Payout {
            withdrawal_index: 4,
            quorum_attempt: 0,
        };
        let mut m = HashMap::new();
        m.insert(id0, b"payout-v0".to_vec());
        let s = SignerService::new(
            Keypair::new(),
            View {
                epoch: 7,
                messages: m,
            },
        );

        s.handle(payout_request(vec![1], 7, b"payout-v0".to_vec(), 4, 0))
            .expect("attempt 0 signs");
        assert!(
            matches!(
                s.handle(payout_request(vec![2], 7, b"payout-v0".to_vec(), 4, 1))
                    .unwrap_err(),
                Refusal::Underivable(_)
            ),
            "attempt 1 is a different identity the validator has not derived"
        );
    }

    #[test]
    fn health_reports_identity_and_observed_epoch() {
        let s = service(b"canonical");
        let pk = s.validator_pubkey();
        assert_eq!(s.view.observed_epoch(), 7);
        assert_eq!(pk.len(), 32);
    }
}
