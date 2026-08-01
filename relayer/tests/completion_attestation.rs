//! What a validator will attest a withdrawal completion for (Phase 7f,
//! ADR-0018 D6).
//!
//! Completion is **terminal and irreversible on-chain**, so this is the most
//! consequential signature the federation produces. These tests are weighted
//! toward what must NOT be attestable: a payout this validator did not make,
//! one it cannot see confirmed at depth, or one at a height it does not
//! observe.

mod common;

use std::sync::{Arc, Mutex};

use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::{BroadcastOutcome, RpcError};
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, NewPayout, NewWithdrawalRequest, ObservedUtxo,
    VaultUtxo, WithdrawalState,
};
use glc_relayer::p2p::completion_view::{CompletionRefusal, CompletionView};
use glc_relayer::withdrawal::executor::{PayoutRpc, TxStatus};
use glc_relayer::withdrawal::federation::InProcessPayoutCollector;

const INDEX: i64 = 4;
const AMOUNT: u64 = 500_000;
const FEE: u64 = 20_000;
const UTXO_VALUE: u64 = 700_000;
const DEST: [u8; 20] = [0x33; 20];
const CHANGE: [u8; 20] = [0x44; 20];
const DEPTH: i64 = 3;
/// Display-order txid, as the database stores it.
const PAYOUT_TXID_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const PAYOUT_HEIGHT: u64 = 4_242;

/// A stand-in Goldcoin node whose answers the test controls.
#[derive(Clone, Default)]
struct FakeNode {
    status: Arc<Mutex<Option<TxStatus>>>,
    unavailable: Arc<Mutex<bool>>,
    calls: Arc<Mutex<usize>>,
}

impl FakeNode {
    fn with(confirmations: i64, height: Option<i64>) -> Self {
        let n = FakeNode::default();
        *n.status.lock().unwrap() = Some(TxStatus {
            confirmations,
            block_hash_hex: Some("aa".repeat(32)),
            block_height: height,
        });
        n
    }
    fn unknown() -> Self {
        FakeNode::default()
    }
    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl PayoutRpc for FakeNode {
    async fn list_unspent(
        &self,
        _: i64,
        _: &[String],
    ) -> Result<Vec<glc_relayer::glc::withdrawal_db::ObservedUtxo>, RpcError> {
        Ok(Vec::new())
    }
    async fn create_raw_transaction(
        &self,
        _: &[(String, i64)],
        _: &[(String, u64)],
    ) -> Result<String, RpcError> {
        unreachable!("completion never builds transactions")
    }
    async fn decode_raw_transaction(
        &self,
        _: &str,
    ) -> Result<glc_relayer::withdrawal::builder::DecodedTx, RpcError> {
        unreachable!("completion never decodes transactions")
    }
    async fn sign_raw_transaction(
        &self,
        _: &str,
        _: &[glc_relayer::glc::rpc::PrevTx],
    ) -> Result<(String, bool), RpcError> {
        unreachable!("completion never signs")
    }
    async fn send_raw_transaction(&self, _: &str) -> Result<BroadcastOutcome, RpcError> {
        unreachable!("completion never broadcasts")
    }
    async fn transaction_confirmations(
        &self,
        _txid_hex: &str,
    ) -> Result<Option<TxStatus>, RpcError> {
        *self.calls.lock().unwrap() += 1;
        if *self.unavailable.lock().unwrap() {
            return Err(RpcError::Transport("node down".into()));
        }
        Ok(self.status.lock().unwrap().clone())
    }
    async fn block_on_main_chain(&self, _: &str) -> Result<bool, RpcError> {
        Ok(true)
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    glc_address: String,
}

/// Seeds a withdrawal driven all the way to a locally-`Completed` payout.
fn fixture(state: WithdrawalState, txid_hex: Option<&str>, height: Option<i64>) -> Fixture {
    let (vault, _) = InProcessPayoutCollector::deterministic_test_vault(3, 2);
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite");
    let mut db = Db::open(&db_path).unwrap();

    let glc_address = glc_relayer::withdrawal::address::encode_p2pkh(&DEST);
    db.observe_withdrawal(&NewWithdrawalRequest {
        withdrawal_index: INDEX,
        pda: [0x55; 32],
        amount_atomic: AMOUNT,
        requester: [0x11; 32],
        glc_address: glc_address.clone(),
        glc_address_hash160: DEST,
        requested_at_slot: 100,
        protocol_version: 1,
        observed_at: 1_000,
        observed_at_slot: 100,
    })
    .unwrap();

    let inputs = vec![VaultUtxo {
        txid: [0x66; 32],
        txid_hex: "66".repeat(32),
        vout: 0,
        amount_atomic: UTXO_VALUE,
        script_pubkey_hex: vault.script_pubkey_hex(),
        confirmations: 10,
    }];
    db.sync_vault_utxos(
        &inputs
            .iter()
            .map(|u| ObservedUtxo {
                txid: u.txid,
                vout: u.vout,
                amount_atomic: u.amount_atomic,
                script_pubkey_hex: u.script_pubkey_hex.clone(),
                confirmations: u.confirmations,
            })
            .collect::<Vec<_>>(),
        1,
        1_000,
    )
    .unwrap();
    db.reserve_utxos(INDEX, &inputs, 1_000).unwrap();

    let change = UTXO_VALUE - AMOUNT - FEE;
    let intent = canonical_payout_intent(
        1,
        INDEX,
        &vault.script_hash160,
        &DEST,
        AMOUNT,
        FEE,
        change,
        &CHANGE,
        0,
        &[0, 1],
        &inputs,
    );
    db.create_payout(&NewPayout {
        withdrawal_index: INDEX,
        vault_script_hash: vault.script_hash160,
        quorum_indices: vec![0, 1],
        quorum_attempt: 0,
        commitment_hash: payout_commitment(&intent),
        intent_bytes: intent,
        fee_atomic: FEE,
        payout_atomic: AMOUNT,
        change_atomic: change,
        change_address: Some(glc_relayer::withdrawal::address::encode_p2pkh(&CHANGE)),
        unsigned_tx_hex: "0100000001deadbeef".to_string(),
        inputs,
        built_at: 1_100,
    })
    .unwrap();

    db.transition_withdrawal(INDEX, WithdrawalState::Validated, 1_010, None)
        .unwrap();
    db.transition_withdrawal(INDEX, WithdrawalState::Building, 1_020, None)
        .unwrap();
    db.transition_withdrawal(INDEX, WithdrawalState::Signing, 1_030, None)
        .unwrap();

    // Drive FORWARD only as far as the requested state. The state machine
    // rejects backwards transitions, and a fixture that forced one would
    // not represent anything the executor can produce.
    if state != WithdrawalState::Signing {
        let t = txid_hex.expect("a post-Signing fixture needs a txid");
        let mut txid = glc_relayer::glc::hex::decode_exact::<32>(t).unwrap();
        txid.reverse();
        db.record_signed_payout(INDEX, "0100signed", &txid, 1_040)
            .unwrap();
        db.record_broadcast(INDEX, 1_050).unwrap();

        if state != WithdrawalState::Broadcast {
            db.record_confirmations(INDEX, 10, Some(&[0xAA; 32]), height)
                .unwrap();
            db.transition_withdrawal(INDEX, WithdrawalState::Confirming, 1_060, None)
                .unwrap();
            if state == WithdrawalState::Completed {
                db.complete_payout(INDEX, 1_070).unwrap();
            }
        }
    }
    assert_eq!(
        db.get_withdrawal(INDEX).unwrap().unwrap().state,
        state,
        "fixture must land exactly on the requested state"
    );

    Fixture {
        _dir: dir,
        db_path,
        glc_address,
    }
}

fn txid_internal() -> [u8; 32] {
    let mut t = glc_relayer::glc::hex::decode_exact::<32>(PAYOUT_TXID_HEX).unwrap();
    t.reverse();
    t
}

async fn attest(
    f: &Fixture,
    node: FakeNode,
    txid: [u8; 32],
    height: u64,
) -> Result<glc_relayer::p2p::completion_view::CompletionAttestation, CompletionRefusal> {
    let mut db = Db::open(&f.db_path).unwrap();
    CompletionView::new(node, DEPTH)
        .attest(&mut db, INDEX as u64, txid, height)
        .await
}

// ---------------------------------------------------------------------

#[tokio::test]
async fn attests_a_payout_it_made_and_can_see_confirmed_at_depth() {
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let a = attest(
        &f,
        FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64)),
        txid_internal(),
        PAYOUT_HEIGHT,
    )
    .await
    .expect("attestation");

    assert_eq!(a.withdrawal_index, INDEX as u64);
    assert_eq!(a.payout_txid, txid_internal());
    assert_eq!(a.payout_height, PAYOUT_HEIGHT);
    assert_eq!(a.amount, AMOUNT, "the amount comes from the local record");
    assert_eq!(
        a.dest_commitment,
        glc_relayer::solana::instruction::destination_commitment(f.glc_address.as_bytes()),
        "the destination commitment hashes the address as stored"
    );
}

#[tokio::test]
async fn refuses_a_payout_below_the_confirmation_depth() {
    // Q2: the same depth that governs local completion. Attesting earlier
    // would declare final a payment that could still be reorged out — and
    // completion is irreversible on-chain.
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let err = attest(
        &f,
        FakeNode::with(DEPTH - 1, Some(PAYOUT_HEIGHT as i64)),
        txid_internal(),
        PAYOUT_HEIGHT,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            CompletionRefusal::InsufficientConfirmations {
                required: DEPTH,
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn accepts_exactly_at_the_depth_boundary() {
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    assert!(attest(
        &f,
        FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64)),
        txid_internal(),
        PAYOUT_HEIGHT
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn refuses_a_payout_this_validator_did_not_make() {
    // The requester names a different txid. Attesting would vouch for a
    // payment this validator has no record of making.
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let node = FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64));
    let err = attest(&f, node.clone(), [0x99; 32], PAYOUT_HEIGHT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CompletionRefusal::TxidMismatch { .. }),
        "{err:?}"
    );
    assert_eq!(
        node.calls(),
        0,
        "the node must not be consulted for a payout this validator never made"
    );
}

#[tokio::test]
async fn refuses_a_height_it_does_not_observe() {
    // The height is recorded on-chain forever, so it is checked against
    // this node's own observation rather than taken on trust.
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let err = attest(
        &f,
        FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64)),
        txid_internal(),
        PAYOUT_HEIGHT + 1,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            CompletionRefusal::HeightMismatch {
                requested: h,
                local: PAYOUT_HEIGHT
            } if h == PAYOUT_HEIGHT + 1
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn refuses_when_its_own_node_has_never_seen_the_payout() {
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let err = attest(&f, FakeNode::unknown(), txid_internal(), PAYOUT_HEIGHT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CompletionRefusal::PayoutUnknownToNode(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn refuses_when_the_node_is_unavailable_rather_than_guessing() {
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let node = FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64));
    *node.unavailable.lock().unwrap() = true;
    let err = attest(&f, node, txid_internal(), PAYOUT_HEIGHT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CompletionRefusal::NodeUnavailable(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn refuses_a_withdrawal_it_has_not_itself_completed() {
    // Every state short of local Completed: this validator has not seen the
    // payment through and must not vouch that anyone else has.
    for state in [
        WithdrawalState::Broadcast,
        WithdrawalState::Confirming,
        WithdrawalState::Signing,
    ] {
        let f = fixture(state, Some(PAYOUT_TXID_HEX), Some(PAYOUT_HEIGHT as i64));
        let node = FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64));
        let err = attest(&f, node.clone(), txid_internal(), PAYOUT_HEIGHT)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CompletionRefusal::NotLocallyCompleted { .. }),
            "{state:?}: {err:?}"
        );
        assert_eq!(node.calls(), 0, "{state:?}: the node must not be consulted");
    }
}

#[tokio::test]
async fn refuses_a_withdrawal_it_has_never_observed() {
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let mut db = Db::open(&f.db_path).unwrap();
    let err = CompletionView::new(FakeNode::with(DEPTH, Some(1)), DEPTH)
        .attest(&mut db, 9_999, txid_internal(), PAYOUT_HEIGHT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CompletionRefusal::UnknownWithdrawal(9_999)),
        "{err:?}"
    );
}

#[tokio::test]
async fn the_amount_and_destination_come_from_local_state_not_the_request() {
    // ADR-0018 D2/D6: these are exactly the facts the signer can verify, so
    // they must never be supplied by the requester. The request carries
    // neither — this pins that the attestation fills them locally.
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let a = attest(
        &f,
        FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64)),
        txid_internal(),
        PAYOUT_HEIGHT,
    )
    .await
    .unwrap();
    assert_eq!(a.amount, AMOUNT);
    assert_ne!(a.dest_commitment, [0u8; 32]);
    assert_eq!(
        a.dest_commitment,
        glc_relayer::solana::instruction::destination_commitment(f.glc_address.as_bytes())
    );
}

// ---------------------------------------------------------------------
// The audit record (ADR-0014 §13.3)
// ---------------------------------------------------------------------

/// A granted completion attestation must leave a record.
///
/// Added in Phase 7l: mutation testing found this grant's audit call site
/// uncovered, because the audit suite exercised only the mint path.
/// Completion is terminal and irreversible on chain, so a validator having
/// attested to it is exactly the kind of thing an incident review needs.
#[tokio::test]
async fn granting_a_completion_attestation_leaves_a_record() {
    use glc_relayer::p2p::service::pb::CompletionSignRequest;
    use glc_relayer::p2p::service::SignerService;

    struct FreshView;
    impl glc_relayer::p2p::policy::LocalView for FreshView {
        fn observed_epoch(&self) -> u64 {
            0
        }
        fn view_is_fresh(&self) -> bool {
            true
        }
        fn derive_message(
            &self,
            _a: glc_relayer::p2p::policy::Action,
            _id: &glc_relayer::p2p::policy::SigningIdentity,
        ) -> Option<Vec<u8>> {
            None
        }
    }

    // Completed, because a validator attests only to a payout IT completed.
    let f = fixture(
        WithdrawalState::Completed,
        Some(PAYOUT_TXID_HEX),
        Some(PAYOUT_HEIGHT as i64),
    );
    let service = SignerService::new(solana_sdk::signature::Keypair::new(), FreshView)
        .with_completion_arm(
            CompletionView::new(FakeNode::with(DEPTH, Some(PAYOUT_HEIGHT as i64)), DEPTH),
            Db::open(&f.db_path).unwrap(),
            [0x33; 32],
            1,
        );

    let mut txid = glc_relayer::glc::hex::decode_exact::<32>(PAYOUT_TXID_HEX).unwrap();
    txid.reverse();

    let (result, grants) =
        common::capture_grants_async(service.handle_completion(CompletionSignRequest {
            request_id: vec![1],
            epoch: 0,
            withdrawal_index: INDEX as u64,
            payout_txid: txid.to_vec(),
            payout_height: PAYOUT_HEIGHT,
            expiry_unix: glc_relayer::p2p::service::now_unix() + 60,
        }))
        .await;

    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(grants.len(), 1, "exactly one record per attestation");
    assert_eq!(grants[0].get("action"), Some("completion"));
    let id = grants[0].get("identity").unwrap();
    assert!(
        id.contains(&INDEX.to_string()),
        "the record must name the withdrawal attested to: {id}"
    );
}
