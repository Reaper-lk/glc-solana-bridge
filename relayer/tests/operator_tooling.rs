//! Phase 7i-0: the governance and vault-sweep signing arms, end to end
//! through [`SignerService`].
//!
//! These exercise the *service* rather than the views, because the property
//! that matters operationally is what a peer gets back over the wire. The
//! views' own guards are unit-tested next to them; what is checked here is
//! that the service reaches those guards, in the right order, and that a
//! signer with no arm attached refuses rather than doing something worse.
//!
//! # Why the fail-closed cases dominate
//!
//! Both arms authorise operations that cannot be undone: a governance
//! signature can rotate the federation or raise the supply ceiling, and a
//! sweep signature helps move the entire vault. Every test here that ends in
//! a refusal is describing a way the bridge does *not* lose control of
//! itself.

use std::path::PathBuf;

use glc_bridge_shared::governance::{
    governance_message, tvl_raise_params, ACTION_CANCEL_ROTATION, ACTION_PROPOSE_ROTATION,
    ACTION_PROPOSE_TVL_RAISE,
};
use sha2::{Digest, Sha256};
use solana_sdk::signature::{Keypair, Signature};

use glc_relayer::p2p::governance_view::{Approval, ApprovalStore, GovernanceView};
use glc_relayer::p2p::policy::{Action, LocalView, Refusal, SigningIdentity};
use glc_relayer::p2p::service::pb::{GovernanceSignRequest, SweepSignRequest};
use glc_relayer::p2p::service::{now_unix, SignerService};

const EPOCH: u64 = 11;
const PROGRAM_ID: [u8; 32] = [0x33; 32];
const PROTOCOL_VERSION: u8 = 1;

struct FixedView {
    epoch: u64,
    fresh: bool,
}

impl LocalView for FixedView {
    fn observed_epoch(&self) -> u64 {
        self.epoch
    }
    fn view_is_fresh(&self) -> bool {
        self.fresh
    }
    fn derive_message(&self, _a: Action, _id: &SigningIdentity) -> Option<Vec<u8>> {
        None
    }
}

fn fresh_view() -> FixedView {
    FixedView {
        epoch: EPOCH,
        fresh: true,
    }
}

fn commitment(params: &[u8]) -> [u8; 32] {
    Sha256::digest(params).into()
}

/// Writes an approval file as `glc-admin approve-*` would.
fn stage(path: &PathBuf, action: u8, params_commitment: [u8; 32], epoch: u64, expiry: i64) {
    let mut store = ApprovalStore::new();
    store.stage(Approval {
        action,
        params_commitment,
        epoch,
        expiry_unix: expiry,
        note: "INC-42 planned rotation".into(),
    });
    std::fs::write(path, store.to_text()).unwrap();
}

fn service_with_governance(path: PathBuf) -> SignerService<FixedView> {
    SignerService::new(Keypair::new(), fresh_view()).with_governance_arm(
        GovernanceView::new(path),
        PROGRAM_ID,
        PROTOCOL_VERSION,
    )
}

fn request(action: u8, params_commitment: [u8; 32]) -> GovernanceSignRequest {
    GovernanceSignRequest {
        request_id: vec![1],
        epoch: EPOCH,
        action: u32::from(action),
        params_commitment: params_commitment.to_vec(),
        expiry_unix: now_unix() + 60,
    }
}

// ---------------------------------------------------------------- governance

#[test]
fn a_signer_with_no_governance_arm_refuses_rather_than_signing() {
    // The state the federation was actually in before this phase: governance
    // requests had nowhere to go. Refusing is right; the failure was that
    // there was no way to configure an arm at all.
    let s = SignerService::new(Keypair::new(), fresh_view());
    let err = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, [0x01; 32]))
        .unwrap_err();
    assert!(matches!(err, Refusal::Underivable(_)), "got {err:?}");
}

#[test]
fn it_signs_exactly_what_its_operator_staged_and_the_signature_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let params = tvl_raise_params(21_000_000_000_000);
    let c = commitment(&params);
    stage(&path, ACTION_PROPOSE_TVL_RAISE, c, EPOCH, now_unix() + 3600);

    let s = service_with_governance(path);
    let resp = s
        .handle_governance(request(ACTION_PROPOSE_TVL_RAISE, c))
        .expect("a staged approval is signed");

    // The signature must verify over the message built from the SIGNER's own
    // program id, protocol version and observed epoch — not the requester's.
    let expected = governance_message(
        PROTOCOL_VERSION,
        &PROGRAM_ID,
        EPOCH,
        ACTION_PROPOSE_TVL_RAISE,
        &c,
    );
    let sig = Signature::try_from(resp.signature.as_slice()).unwrap();
    assert!(
        sig.verify(&resp.validator_pubkey, &expected),
        "the signature must verify over the locally derived governance message"
    );
    assert_eq!(resp.validator_pubkey, s.validator_pubkey().to_vec());
}

#[test]
fn an_unapproved_proposal_is_refused_even_for_an_approved_action() {
    // A rotation approval authorises ONE validator set, not "rotations".
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    stage(
        &path,
        ACTION_PROPOSE_ROTATION,
        [0xAA; 32],
        EPOCH,
        now_unix() + 3600,
    );

    let s = service_with_governance(path);
    let err = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, [0xBB; 32]))
        .unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

#[test]
fn an_approval_for_one_action_does_not_authorise_another() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let c = [0xAA; 32];
    stage(&path, ACTION_PROPOSE_ROTATION, c, EPOCH, now_unix() + 3600);

    let s = service_with_governance(path);
    // Same commitment bytes, different action: still refused, because the
    // approval is keyed by action as well as parameters.
    let err = s
        .handle_governance(request(ACTION_CANCEL_ROTATION, c))
        .unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

#[test]
fn a_non_governance_action_never_reaches_the_governance_domain() {
    // Signing action 0x01 under the governance domain tag would produce a
    // governance signature for a mint.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    stage(&path, 0x01, [0xAA; 32], EPOCH, now_unix() + 3600);

    let s = service_with_governance(path);
    let err = s.handle_governance(request(0x01, [0xAA; 32])).unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

#[test]
fn an_expired_request_is_refused_before_the_approval_is_even_read() {
    let s = service_with_governance(PathBuf::from("/nonexistent/approvals"));
    let mut req = request(ACTION_PROPOSE_ROTATION, [0xAA; 32]);
    req.expiry_unix = now_unix() - 1;
    assert!(matches!(
        s.handle_governance(req).unwrap_err(),
        Refusal::Expired { .. }
    ));
}

#[test]
fn a_stale_view_refuses_governance() {
    // A signer that cannot see the chain must not authorise a change to the
    // federation it may no longer be current with.
    let s = SignerService::new(
        Keypair::new(),
        FixedView {
            epoch: EPOCH,
            fresh: false,
        },
    )
    .with_governance_arm(
        GovernanceView::new(PathBuf::from("/nonexistent")),
        PROGRAM_ID,
        PROTOCOL_VERSION,
    );
    assert_eq!(
        s.handle_governance(request(ACTION_PROPOSE_ROTATION, [0xAA; 32]))
            .unwrap_err(),
        Refusal::StaleView
    );
}

#[test]
fn an_approval_does_not_survive_a_rotation() {
    // Staged under epoch 10, requested under 11: the federation changed
    // between the operator's decision and the request.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let c = [0xAA; 32];
    stage(
        &path,
        ACTION_PROPOSE_ROTATION,
        c,
        EPOCH - 1,
        now_unix() + 3600,
    );

    let s = service_with_governance(path);
    let err = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, c))
        .unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

#[test]
fn a_retry_is_idempotent_but_a_second_proposal_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let first = [0xAA; 32];
    stage(
        &path,
        ACTION_PROPOSE_ROTATION,
        first,
        EPOCH,
        now_unix() + 3600,
    );

    let s = service_with_governance(path.clone());
    let a = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, first))
        .unwrap();
    let b = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, first))
        .unwrap();
    assert_eq!(
        a.signature, b.signature,
        "a retry returns the same signature"
    );

    // The operator now stages a DIFFERENT rotation. The signer has already
    // committed to one and must not equivocate, even though the new approval
    // is perfectly valid on its face.
    let second = [0xBB; 32];
    stage(
        &path,
        ACTION_PROPOSE_ROTATION,
        second,
        EPOCH,
        now_unix() + 3600,
    );
    let err = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, second))
        .unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

#[test]
fn revoking_an_approval_takes_effect_without_a_restart() {
    // Mid-incident, an operator must be able to withdraw consent from a
    // running signer. The file is re-read on every request for exactly this.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approvals");
    let c = [0xAA; 32];
    stage(&path, ACTION_PROPOSE_ROTATION, c, EPOCH, now_unix() + 3600);

    let s = service_with_governance(path.clone());
    std::fs::remove_file(&path).unwrap();
    let err = s
        .handle_governance(request(ACTION_PROPOSE_ROTATION, c))
        .unwrap_err();
    assert!(matches!(err, Refusal::GovernanceRefused(_)), "got {err:?}");
}

// --------------------------------------------------------------- vault sweep

fn sweep_request() -> SweepSignRequest {
    SweepSignRequest {
        request_id: vec![9],
        epoch: EPOCH,
        // Never parsed in these cases: every one of them is refused before
        // the transaction is looked at.
        unsigned_tx_hex: String::new(),
        expiry_unix: now_unix() + 60,
    }
}

#[tokio::test]
async fn a_signer_with_no_sweep_arm_refuses_every_sweep() {
    // The default for a signer that was never configured for sweeps —
    // including every signer that holds no vault key at all.
    let s = SignerService::new(Keypair::new(), fresh_view());
    let err = s.handle_sweep(sweep_request()).await.unwrap_err();
    assert!(matches!(err, Refusal::Underivable(_)), "got {err:?}");
}

#[tokio::test]
async fn a_sweep_under_a_different_epoch_is_refused() {
    let s = SignerService::new(Keypair::new(), fresh_view());
    let mut req = sweep_request();
    req.epoch = EPOCH + 1;
    assert_eq!(
        s.handle_sweep(req).await.unwrap_err(),
        Refusal::EpochMismatch {
            requested: EPOCH + 1,
            observed: EPOCH
        }
    );
}

#[tokio::test]
async fn an_expired_sweep_request_is_refused() {
    let s = SignerService::new(Keypair::new(), fresh_view());
    let mut req = sweep_request();
    req.expiry_unix = now_unix() - 1;
    assert!(matches!(
        s.handle_sweep(req).await.unwrap_err(),
        Refusal::Expired { .. }
    ));
}

#[tokio::test]
async fn a_stale_view_refuses_a_sweep() {
    let s = SignerService::new(
        Keypair::new(),
        FixedView {
            epoch: EPOCH,
            fresh: false,
        },
    );
    assert_eq!(
        s.handle_sweep(sweep_request()).await.unwrap_err(),
        Refusal::StaleView
    );
}
