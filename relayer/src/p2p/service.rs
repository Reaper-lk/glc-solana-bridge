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

use super::completion_view::{CompletionRefusal, CompletionView};
use super::payout_view::{PartialSigner, PayoutRefusal, PayoutView};
use super::policy::{
    self, Action, Decision, LocalView, Refusal, SeenSet, SigningIdentity, SigningRequest,
};
use super::ratelimit::RateLimiter;
use crate::glc::db::Db;

pub mod pb {
    tonic::include_proto!("glc.federation.v1");
}

use pb::federation_signer_server::FederationSigner;
use pb::{CompletionSignRequest, CompletionSignResponse};
use pb::{
    HealthRequest, HealthResponse, PayoutSignRequest, PayoutSignResponse, SignRequest, SignResponse,
};

pub fn now_unix() -> i64 {
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
    limiter: Arc<Mutex<RateLimiter>>,
    /// The Goldcoin payout arm (Phase 7e, ADR-0017). `None` means this
    /// signer serves mint requests only and refuses payout requests
    /// outright — the correct behaviour for a validator that holds no vault
    /// key, and a fail-closed default rather than a silent no-op.
    payout: Option<PayoutArm>,
    /// The completion-attestation arm (Phase 7f, ADR-0018). `None` refuses
    /// completion requests, for the same fail-closed reason.
    completion: Option<CompletionArm>,
}

/// The completion-attestation half of a signer. Needs its own database
/// handle and its own Goldcoin node, like the payout arm.
struct CompletionArm {
    view: Box<dyn ErasedCompletionView>,
    db: Arc<tokio::sync::Mutex<Db>>,
    /// The program this deployment targets, bound into every attestation so
    /// a signature cannot be replayed against a different bridge.
    program_id: [u8; 32],
    protocol_version: u8,
}

#[tonic::async_trait]
trait ErasedCompletionView: Send + Sync {
    async fn attest(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
    ) -> Result<super::completion_view::CompletionAttestation, CompletionRefusal>;
}

#[tonic::async_trait]
impl<R: crate::withdrawal::executor::PayoutRpc + Send + Sync + 'static> ErasedCompletionView
    for CompletionView<R>
{
    async fn attest(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        payout_txid: [u8; 32],
        payout_height: u64,
    ) -> Result<super::completion_view::CompletionAttestation, CompletionRefusal> {
        CompletionView::attest(self, db, withdrawal_index, payout_txid, payout_height).await
    }
}

/// The vault-signing half of a signer, kept separate because it is optional
/// and because it needs its own database handle and its own Goldcoin node.
struct PayoutArm {
    view: Box<dyn ErasedPayoutView>,
    /// A dedicated connection: `rusqlite::Connection` is `Send` but not
    /// `Sync`, and payout signing must not contend with mint signing.
    db: Arc<tokio::sync::Mutex<Db>>,
}

/// Erases the [`PartialSigner`] type parameter so `SignerService` does not
/// gain a second one purely for an optional arm.
#[tonic::async_trait]
trait ErasedPayoutView: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn sign_payout(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        proposer_index: usize,
        now_unix: i64,
    ) -> Result<super::payout_view::PayoutPartial, PayoutRefusal>;
}

#[tonic::async_trait]
impl<S: PartialSigner + Send + Sync + 'static> ErasedPayoutView for PayoutView<S> {
    async fn sign_payout(
        &self,
        db: &mut Db,
        withdrawal_index: u64,
        quorum_attempt: u32,
        canonical_intent: &[u8],
        unsigned_tx_hex: &str,
        proposer_index: usize,
        now_unix: i64,
    ) -> Result<super::payout_view::PayoutPartial, PayoutRefusal> {
        PayoutView::sign_payout(
            self,
            db,
            withdrawal_index,
            quorum_attempt,
            canonical_intent,
            unsigned_tx_hex,
            proposer_index,
            now_unix,
        )
        .await
    }
}

impl<V: LocalView + Send + Sync + 'static> SignerService<V> {
    /// Constructs the service around **one** validator identity.
    ///
    /// There is deliberately no constructor taking several keys: holding
    /// more than one validator identity in a process is precisely the
    /// bootstrap topology Phase 7c exists to retire.
    pub fn new(keypair: Keypair, view: V) -> Self {
        Self::with_rate_limits(
            keypair,
            view,
            super::ratelimit::REFILL_PER_SECOND,
            super::ratelimit::BURST,
        )
    }

    /// Same, with explicit limits.
    ///
    /// Exists so tests can pin the limiter's behaviour instead of racing the
    /// refill clock — a test that floods the real server at production
    /// limits passes or fails depending on how fast the machine is, which is
    /// not a test of anything.
    pub fn with_rate_limits(keypair: Keypair, view: V, refill_per_second: f64, burst: f64) -> Self {
        SignerService {
            keypair,
            view,
            seen: Arc::new(Mutex::new(SeenSet::new())),
            limiter: Arc::new(Mutex::new(RateLimiter::with_limits(
                refill_per_second,
                burst,
            ))),
            payout: None,
            completion: None,
        }
    }

    /// Attaches the completion-attestation arm (Phase 7f, ADR-0018).
    ///
    /// `db` and the view's Goldcoin node must both be **this validator's
    /// own** — a completion attestation is the last word on whether a
    /// payment happened, so inheriting the requester's view would make the
    /// check circular.
    pub fn with_completion_arm<
        R: crate::withdrawal::executor::PayoutRpc + Send + Sync + 'static,
    >(
        mut self,
        view: CompletionView<R>,
        db: Db,
        program_id: [u8; 32],
        protocol_version: u8,
    ) -> Self {
        self.completion = Some(CompletionArm {
            view: Box::new(view),
            db: Arc::new(tokio::sync::Mutex::new(db)),
            program_id,
            protocol_version,
        });
        self
    }

    /// Handles a completion attestation request. Exposed directly so the
    /// decision path is testable without standing up a server.
    pub async fn handle_completion(
        &self,
        req: CompletionSignRequest,
    ) -> Result<CompletionSignResponse, Refusal> {
        let now = now_unix();
        if now > req.expiry_unix {
            return Err(Refusal::Expired {
                expiry_unix: req.expiry_unix,
                now,
            });
        }
        if !self.view.view_is_fresh() {
            return Err(Refusal::StaleView);
        }
        let observed = self.view.observed_epoch();
        if req.epoch != observed {
            return Err(Refusal::EpochMismatch {
                requested: req.epoch,
                observed,
            });
        }

        let Some(arm) = &self.completion else {
            return Err(Refusal::Underivable(
                "this validator cannot attest withdrawal completions",
            ));
        };

        let payout_txid: [u8; 32] = req
            .payout_txid
            .as_slice()
            .try_into()
            .map_err(|_| Refusal::Underivable("payout txid is not 32 bytes"))?;

        let mut db = arm.db.lock().await;
        let attestation = arm
            .view
            .attest(
                &mut db,
                req.withdrawal_index,
                payout_txid,
                req.payout_height,
            )
            .await
            .map_err(|refusal| {
                tracing::warn!(
                    withdrawal_index = req.withdrawal_index,
                    %refusal,
                    "refused a withdrawal completion attestation"
                );
                Refusal::CompletionRefused(refusal.to_string())
            })?;

        // The message is built from the ATTESTATION — this validator's own
        // verified facts — never from the request.
        let message = glc_bridge_shared::claim::withdrawal_completion_message(
            arm.protocol_version,
            &arm.program_id,
            observed,
            attestation.withdrawal_index,
            &attestation.payout_txid,
            attestation.payout_height,
            attestation.amount,
            &attestation.dest_commitment,
        );

        Ok(CompletionSignResponse {
            request_id: req.request_id,
            validator_pubkey: self.validator_pubkey().to_vec(),
            signature: self.keypair.sign_message(&message).as_ref().to_vec(),
        })
    }

    /// Attaches the Goldcoin payout arm (Phase 7e).
    ///
    /// `db` must be this validator's OWN database and `view` must be backed
    /// by this validator's OWN Goldcoin node (ADR-0017 E2). Sharing the
    /// relayer's node would mean inheriting the requester's view of the
    /// chain, which defeats the independent validation the whole design
    /// rests on.
    pub fn with_payout_arm<S: PartialSigner + Send + Sync + 'static>(
        mut self,
        view: PayoutView<S>,
        db: Db,
    ) -> Self {
        self.payout = Some(PayoutArm {
            view: Box::new(view),
            db: Arc::new(tokio::sync::Mutex::new(db)),
        });
        self
    }

    /// Handles a payout signing request. Exposed directly so the decision
    /// path is testable without standing up a server.
    pub async fn handle_payout(
        &self,
        req: PayoutSignRequest,
    ) -> Result<PayoutSignResponse, Refusal> {
        let now = now_unix();
        if now > req.expiry_unix {
            return Err(Refusal::Expired {
                expiry_unix: req.expiry_unix,
                now,
            });
        }
        // The epoch check applies identically to payouts: a validator must
        // not authorize a spend under a federation revision it does not
        // agree with.
        if !self.view.view_is_fresh() {
            return Err(Refusal::StaleView);
        }
        let observed = self.view.observed_epoch();
        if req.epoch != observed {
            return Err(Refusal::EpochMismatch {
                requested: req.epoch,
                observed,
            });
        }

        let Some(arm) = &self.payout else {
            // Fail closed: a signer with no vault key must say so, not
            // return something that looks like agreement.
            return Err(Refusal::Underivable(
                "this validator holds no vault key and cannot sign payouts",
            ));
        };

        let mut db = arm.db.lock().await;
        match arm
            .view
            .sign_payout(
                &mut db,
                req.withdrawal_index,
                req.quorum_attempt,
                &req.canonical_intent,
                &req.unsigned_tx_hex,
                req.proposer_index as usize,
                now,
            )
            .await
        {
            Ok(partial) => Ok(PayoutSignResponse {
                request_id: req.request_id,
                validator_pubkey: self.validator_pubkey().to_vec(),
                vault_pubkey: partial.vault_pubkey.to_vec(),
                signatures: partial.signatures,
            }),
            Err(refusal) => {
                tracing::warn!(
                    withdrawal_index = req.withdrawal_index,
                    quorum_attempt = req.quorum_attempt,
                    %refusal,
                    "refused a vault payout signing request"
                );
                Err(Refusal::PayoutRefused(refusal.to_string()))
            }
        }
    }

    pub fn validator_pubkey(&self) -> [u8; 32] {
        self.keypair.pubkey().to_bytes()
    }

    /// Charges one request against `peer`'s allowance.
    ///
    /// Separate from [`Self::handle`] and applied *before* it, so an
    /// over-limit peer is turned away without the service doing the
    /// re-derivation work that makes signing expensive.
    pub fn check_rate_limit(&self, peer: &str) -> Result<(), Refusal> {
        if self.limiter.lock().unwrap().check(peer) {
            Ok(())
        } else {
            Err(Refusal::RateLimited)
        }
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

/// A stable key for the peer behind a request, for rate-limiting purposes.
///
/// Prefers the mTLS client certificate: it is the federation-issued identity
/// and survives NAT, proxies, and reconnection, whereas an address does not.
/// The certificate is only *fingerprinted*, never parsed — no X.509 parser
/// is on the request path, and authenticating the certificate is already
/// TLS's job, done before this code runs.
///
/// Falls back to the remote **address without its port**, since a per-port
/// key would mint a fresh bucket for every new connection and limit nothing.
fn peer_key<T>(request: &Request<T>) -> String {
    use sha2::{Digest, Sha256};
    if let Some(certs) = request.peer_certs() {
        if let Some(leaf) = certs.first() {
            let digest = Sha256::digest(&**leaf);
            return format!("cert:{}", hex_prefix(&digest));
        }
    }
    match request.remote_addr() {
        Some(addr) => format!("addr:{}", addr.ip()),
        // No certificate and no address: one shared bucket, which is
        // deliberately the most restrictive outcome rather than a bypass.
        None => "unidentified".to_string(),
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(16).fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[tonic::async_trait]
impl<V: LocalView + Send + Sync + 'static> FederationSigner for SignerService<V> {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let peer = peer_key(&request);
        // Charged before `handle`, so an over-limit peer never reaches the
        // expensive re-derivation path.
        if let Err(refusal) = self.check_rate_limit(&peer) {
            tracing::warn!(%peer, "rate-limited a federation signing request");
            // `resource_exhausted`, deliberately NOT `failed_precondition`:
            // the collector treats the latter as a genuine disagreement and
            // stops retrying. Being throttled is transient and a later tick
            // should try again.
            return Err(Status::resource_exhausted(refusal.to_string()));
        }
        match self.handle(request.into_inner()) {
            Ok(resp) => Ok(Response::new(resp)),
            // A refusal is a first-class, logged outcome: it means this
            // validator's view disagrees with a peer's, which is either a
            // bug or an attack — never routine.
            Err(refusal) => {
                tracing::warn!(%peer, %refusal, "refused a federation signing request");
                Err(Status::failed_precondition(refusal.to_string()))
            }
        }
    }

    async fn sign_payout(
        &self,
        request: Request<PayoutSignRequest>,
    ) -> Result<Response<PayoutSignResponse>, Status> {
        let peer = peer_key(&request);
        if let Err(refusal) = self.check_rate_limit(&peer) {
            tracing::warn!(%peer, "rate-limited a payout signing request");
            return Err(Status::resource_exhausted(refusal.to_string()));
        }
        match self.handle_payout(request.into_inner()).await {
            Ok(resp) => Ok(Response::new(resp)),
            Err(refusal) => {
                tracing::warn!(%peer, %refusal, "refused a payout signing request");
                Err(Status::failed_precondition(refusal.to_string()))
            }
        }
    }

    async fn sign_completion(
        &self,
        request: Request<CompletionSignRequest>,
    ) -> Result<Response<CompletionSignResponse>, Status> {
        let peer = peer_key(&request);
        if let Err(refusal) = self.check_rate_limit(&peer) {
            tracing::warn!(%peer, "rate-limited a completion signing request");
            return Err(Status::resource_exhausted(refusal.to_string()));
        }
        match self.handle_completion(request.into_inner()).await {
            Ok(resp) => Ok(Response::new(resp)),
            Err(refusal) => {
                tracing::warn!(%peer, %refusal, "refused a completion signing request");
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
            payout: None,
            completion: None,
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
            limiter: Arc::new(Mutex::new(RateLimiter::new())),
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
    fn a_peer_exceeding_its_allowance_is_rate_limited() {
        let s = service(b"canonical");
        let mut refused = 0;
        // Well past the burst allowance.
        for _ in 0..(super::super::ratelimit::BURST as usize + 5) {
            if s.check_rate_limit("addr:10.0.0.1").is_err() {
                refused += 1;
            }
        }
        assert!(
            refused >= 5,
            "the limit must actually bite, got {refused} refusals"
        );
        assert_eq!(
            s.check_rate_limit("addr:10.0.0.1"),
            Err(Refusal::RateLimited)
        );
    }

    #[test]
    fn rate_limiting_is_per_peer_so_one_peer_cannot_starve_the_federation() {
        let s = service(b"canonical");
        for _ in 0..(super::super::ratelimit::BURST as usize + 5) {
            let _ = s.check_rate_limit("addr:10.0.0.1");
        }
        assert!(s.check_rate_limit("addr:10.0.0.1").is_err());
        assert!(
            s.check_rate_limit("addr:10.0.0.2").is_ok(),
            "an unrelated peer must still be served"
        );
    }

    #[test]
    fn rate_limiting_does_not_consume_the_signing_path() {
        // Being throttled must not record anything in the seen-set, or a
        // throttled request could poison a later legitimate one.
        let s = service(b"canonical");
        for _ in 0..(super::super::ratelimit::BURST as usize + 5) {
            let _ = s.check_rate_limit("addr:10.0.0.1");
        }
        assert!(s.seen.lock().unwrap().is_empty());
        // And the signing path itself still works for a fresh request.
        assert!(s
            .handle(mint_request(vec![1], 7, b"canonical".to_vec(), TXID, 1))
            .is_ok());
    }

    #[test]
    fn a_peer_key_without_a_certificate_or_address_is_not_a_bypass() {
        // A request carrying neither must land in a bucket, not skip the
        // limiter — the most restrictive outcome, not the most permissive.
        let req = Request::new(mint_request(vec![1], 7, b"m".to_vec(), TXID, 1));
        assert_eq!(peer_key(&req), "unidentified");

        let s = service(b"canonical");
        for _ in 0..(super::super::ratelimit::BURST as usize + 5) {
            let _ = s.check_rate_limit("unidentified");
        }
        assert!(s.check_rate_limit("unidentified").is_err());
    }

    #[test]
    fn health_reports_identity_and_observed_epoch() {
        let s = service(b"canonical");
        let pk = s.validator_pubkey();
        assert_eq!(s.view.observed_epoch(), 7);
        assert_eq!(pk.len(), 32);
    }
}
