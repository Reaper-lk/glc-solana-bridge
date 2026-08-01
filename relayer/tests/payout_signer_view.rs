//! What a payout signer will and will not sign (Phase 7e, ADR-0017 D3/D4).
//!
//! Drives [`PayoutView`] against a real SQLite database with a recording
//! stand-in for the signer's Goldcoin node, so the decision path exercised
//! here is the one production runs.
//!
//! The properties under test are the ones that make distributed signing
//! safe: a signer answers from **its own** state, refuses anything it did
//! not itself derive, and takes input amounts **only** from its own UTXO
//! rows — because the legacy sighash does not cover them (ADR-0017 §2.5).

mod common;

use std::sync::{Arc, Mutex};

use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::PrevTx;
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, NewPayout, NewWithdrawalRequest, ObservedUtxo,
    VaultUtxo, WithdrawalState,
};
use glc_relayer::p2p::payout_view::{PartialSigner, PayoutRefusal, PayoutView};
use glc_relayer::withdrawal::federation::InProcessPayoutCollector;
use glc_relayer::withdrawal::multisig::{Transaction, TxInput, TxOutput};
use glc_relayer::withdrawal::vault::MultisigVault;

const INDEX: i64 = 4;
const AMOUNT: u64 = 500_000;
const FEE: u64 = 20_000;
const UTXO_VALUE: u64 = 700_000;
const DEST: [u8; 20] = [0x33; 20];
const CHANGE: [u8; 20] = [0x44; 20];
const PROTOCOL_VERSION: u8 = 1;
const QUORUM: &[u8] = &[0, 1];

/// One recorded call: the transaction the node was asked to sign, and the
/// `prevtxs` it was given.
type SignCall = (String, Vec<PrevTx>);

/// Records what the signer's node was asked to sign, so a test can assert
/// on the `prevtxs` actually used rather than on what was requested.
#[derive(Clone, Default)]
struct RecordingSigner {
    seen: Arc<Mutex<Vec<SignCall>>>,
    /// Vault keys, so the stand-in produces genuine partial signatures.
    keys: Arc<Mutex<Option<(MultisigVault, u8)>>>,
}

impl RecordingSigner {
    fn last(&self) -> SignCall {
        self.seen.lock().unwrap().last().cloned().expect("no call")
    }
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl PartialSigner for RecordingSigner {
    async fn sign_partial(
        &self,
        unsigned_tx_hex: &str,
        prevtxs: &[PrevTx],
    ) -> Result<String, String> {
        self.seen
            .lock()
            .unwrap()
            .push((unsigned_tx_hex.to_string(), prevtxs.to_vec()));

        // Produce a genuine partially-signed transaction: one signature,
        // placed exactly as a node would place it.
        let (vault, index) = self.keys.lock().unwrap().clone().expect("keys");
        let mut tx = Transaction::parse_hex(unsigned_tx_hex).map_err(|e| e.to_string())?;
        let secret = deterministic_secret(index);
        for i in 0..tx.inputs.len() {
            let sighash = tx.sighash_all(i, &vault.redeem_script);
            let msg = libsecp256k1::Message::parse(&sighash);
            let (sig, _) = libsecp256k1::sign(&msg, &secret);
            let mut der = sig.serialize_der().as_ref().to_vec();
            der.push(glc_relayer::withdrawal::multisig::SIGHASH_ALL);

            let mut script = vec![0x00u8];
            script.push(der.len() as u8);
            script.extend_from_slice(&der);
            // OP_PUSHDATA1 for the redeem script (105 bytes > 0x4b).
            script.push(0x4c);
            script.push(vault.redeem_script.len() as u8);
            script.extend_from_slice(&vault.redeem_script);
            tx.inputs[i].script_sig = script;
        }
        Ok(tx.serialize_hex())
    }
}

fn deterministic_secret(i: u8) -> libsecp256k1::SecretKey {
    let mut seed = [0u8; 32];
    seed[31] = i + 1;
    seed[0] = 0x42;
    libsecp256k1::SecretKey::parse(&seed).unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    vault: MultisigVault,
    cfg: glc_relayer::withdrawal::config::WithdrawalConfig,
    intent: Vec<u8>,
    unsigned_hex: String,
    signer: RecordingSigner,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Seeds a withdrawal at `Signing` with a self-consistent payout.
fn fixture(quorum: &[u8], quorum_attempt: u32, state: WithdrawalState) -> Fixture {
    let (vault, _) = InProcessPayoutCollector::deterministic_test_vault(3, 2);
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("signer.sqlite");
    let mut db = Db::open(&db_path).unwrap();

    db.observe_withdrawal(&NewWithdrawalRequest {
        withdrawal_index: INDEX,
        pda: [0x55; 32],
        amount_atomic: AMOUNT,
        requester: [0x11; 32],
        glc_address: glc_relayer::withdrawal::address::encode_p2pkh(&DEST),
        glc_address_hash160: DEST,
        requested_at_slot: 100,
        protocol_version: PROTOCOL_VERSION,
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
        PROTOCOL_VERSION,
        INDEX,
        &vault.script_hash160,
        &DEST,
        AMOUNT,
        FEE,
        change,
        &CHANGE,
        quorum_attempt,
        quorum,
        &inputs,
    );

    // A genuine unsigned transaction over the reserved input.
    let unsigned = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: {
                let mut t = inputs[0].txid;
                t.reverse();
                t
            },
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        }],
        outputs: vec![
            TxOutput {
                value: AMOUNT,
                script_pubkey: glc_relayer::glc::hex::decode_vec(
                    &glc_relayer::withdrawal::address::p2pkh_script_hex(&DEST),
                )
                .unwrap(),
            },
            TxOutput {
                value: change,
                script_pubkey: glc_relayer::glc::hex::decode_vec(
                    &glc_relayer::withdrawal::address::p2pkh_script_hex(&CHANGE),
                )
                .unwrap(),
            },
        ],
        lock_time: 0,
    };
    let unsigned_hex = unsigned.serialize_hex();

    db.create_payout(&NewPayout {
        withdrawal_index: INDEX,
        vault_script_hash: vault.script_hash160,
        quorum_indices: quorum.to_vec(),
        quorum_attempt,
        commitment_hash: payout_commitment(&intent),
        intent_bytes: intent.clone(),
        fee_atomic: FEE,
        payout_atomic: AMOUNT,
        change_atomic: change,
        change_address: Some(glc_relayer::withdrawal::address::encode_p2pkh(&CHANGE)),
        unsigned_tx_hex: unsigned_hex.clone(),
        inputs,
        built_at: 1_100,
    })
    .unwrap();

    db.transition_withdrawal(INDEX, WithdrawalState::Validated, 1_010, None)
        .unwrap();
    db.transition_withdrawal(INDEX, WithdrawalState::Building, 1_020, None)
        .unwrap();
    for (step, at) in [
        (WithdrawalState::Signing, 1_030),
        (WithdrawalState::Broadcast, 1_040),
        (WithdrawalState::Confirming, 1_050),
    ] {
        if state == WithdrawalState::Building {
            break;
        }
        db.transition_withdrawal(INDEX, step, at, None).unwrap();
        if step == state {
            break;
        }
    }

    let signer = RecordingSigner::default();
    *signer.keys.lock().unwrap() = Some((vault.clone(), 0));

    let cfg = glc_relayer::withdrawal::config::WithdrawalConfig::validate(
        glc_relayer::withdrawal::config::RawWithdrawalConfig {
            vault_redeem_script_hex: vault.redeem_script_hex(),
            vault_address: vault.address.clone(),
            change_address: vault.address.clone(),
            fee_rate_per_kb: 100_000,
            dust_threshold_atomic: 5_400,
            vault_min_confirmations: 1,
            confirmation_depth: 2,
            max_inputs_per_payout: 20,
            reservation_timeout_secs: 900,
            discovery_commitment: "finalized".into(),
            poll_interval_ms: 500,
        },
    )
    .unwrap();

    Fixture {
        _dir: dir,
        db_path,
        cfg,
        vault,
        intent,
        unsigned_hex,
        signer,
    }
}

fn view(f: &Fixture, signer_index: u8) -> PayoutView<RecordingSigner> {
    PayoutView::new(f.cfg.clone(), signer_index, f.signer.clone()).unwrap()
}

async fn sign(
    f: &Fixture,
    signer_index: u8,
    attempt: u32,
    intent: &[u8],
    unsigned: &str,
) -> Result<glc_relayer::p2p::payout_view::PayoutPartial, PayoutRefusal> {
    let mut db = Db::open(&f.db_path).unwrap();
    view(f, signer_index)
        .sign_payout(&mut db, INDEX as u64, attempt, intent, unsigned, 0, now())
        .await
}

// ---------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------

#[tokio::test]
async fn signs_a_payout_it_independently_agrees_with() {
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let partial = sign(&f, 0, 0, &f.intent, &f.unsigned_hex).await.unwrap();
    assert_eq!(partial.vault_pubkey, f.vault.signer_pubkeys[0]);
    assert_eq!(partial.signatures.len(), 1, "one signature per input");
    assert_eq!(f.signer.calls(), 1);
}

// ---------------------------------------------------------------------
// D4: amounts come only from local state
// ---------------------------------------------------------------------

#[tokio::test]
async fn input_details_come_from_local_rows_not_from_the_request() {
    // ADR-0017 §2.5/D4: the legacy sighash does not cover input amounts, so
    // a signature is no evidence about value. The prevtxs handed to the
    // node must therefore be built entirely from this validator's own
    // `vault_utxos` rows.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    sign(&f, 0, 0, &f.intent, &f.unsigned_hex).await.unwrap();

    let (signed_hex, prevtxs) = f.signer.last();
    assert_eq!(
        signed_hex, f.unsigned_hex,
        "the signer signs the transaction IT loaded, not the requester's copy"
    );
    assert_eq!(prevtxs.len(), 1);
    assert_eq!(prevtxs[0].txid, "66".repeat(32), "outpoint from local rows");
    assert_eq!(prevtxs[0].vout, 0);
    assert_eq!(
        prevtxs[0].script_pub_key,
        f.vault.script_pubkey_hex(),
        "scriptPubKey from local rows"
    );
    assert_eq!(
        prevtxs[0].redeem_script,
        f.vault.redeem_script_hex(),
        "redeem script from local configuration"
    );
}

// ---------------------------------------------------------------------
// Signer disagreement
// ---------------------------------------------------------------------

#[tokio::test]
async fn refuses_an_intent_it_does_not_independently_recompute() {
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let mut forged = f.intent.clone();
    let n = forged.len();
    forged[n - 1] ^= 0xFF;
    let err = sign(&f, 0, 0, &forged, &f.unsigned_hex).await.unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::IntentMismatch { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0, "the node must not be reached");
}

#[tokio::test]
async fn refuses_an_unsigned_transaction_its_own_executor_did_not_build() {
    // The intent can match while the transaction differs — for instance a
    // different change output. Both are compared for exactly this reason.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let mut tampered = Transaction::parse_hex(&f.unsigned_hex).unwrap();
    tampered.outputs[0].value += 1;
    let err = sign(&f, 0, 0, &f.intent, &tampered.serialize_hex())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::UnsignedTxMismatch { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0, "the node must not be reached");
}

#[tokio::test]
async fn refuses_a_redirected_destination_even_with_a_matching_amount() {
    // The most dangerous single tamper: same value, different recipient.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let mut tampered = Transaction::parse_hex(&f.unsigned_hex).unwrap();
    tampered.outputs[0].script_pubkey = glc_relayer::glc::hex::decode_vec(
        &glc_relayer::withdrawal::address::p2pkh_script_hex(&[0xCC; 20]),
    )
    .unwrap();
    let err = sign(&f, 0, 0, &f.intent, &tampered.serialize_hex())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::UnsignedTxMismatch { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0);
}

// ---------------------------------------------------------------------
// ADR-0015: designation
// ---------------------------------------------------------------------

#[tokio::test]
async fn refuses_a_quorum_attempt_it_has_not_designated() {
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let err = sign(&f, 0, 1, &f.intent, &f.unsigned_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            PayoutRefusal::QuorumAttemptMismatch {
                requested: 1,
                local: 0
            }
        ),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0);
}

#[tokio::test]
async fn refuses_when_this_signer_is_not_in_the_designated_quorum() {
    // Signer 2 is not designated. Signing anyway would produce a signature
    // that could be collected into a quorum nobody designated — and the txid
    // depends on which quorum signs.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let err = sign(&f, 2, 0, &f.intent, &f.unsigned_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::NotDesignated { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0);
}

// ---------------------------------------------------------------------
// State and stale views
// ---------------------------------------------------------------------

#[tokio::test]
async fn refuses_a_payout_outside_the_signing_window() {
    for state in [WithdrawalState::Broadcast, WithdrawalState::Confirming] {
        let f = fixture(QUORUM, 0, state);
        let err = sign(&f, 0, 0, &f.intent, &f.unsigned_hex)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PayoutRefusal::NotSignable { .. }),
            "{state:?}: {err:?}"
        );
        assert_eq!(f.signer.calls(), 0);
    }
}

#[tokio::test]
async fn refuses_a_withdrawal_it_has_never_observed() {
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let mut db = Db::open(&f.db_path).unwrap();
    let err = view(&f, 0)
        .sign_payout(&mut db, 9_999, 0, &f.intent, &f.unsigned_hex, 0, now())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::UnknownWithdrawal(9_999)),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_stale_utxo_view_halts_rather_than_signing() {
    // The signer's own UTXO row drifted from what was committed. Signing
    // would authorize a spend of inputs it can no longer confirm.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    {
        let conn = rusqlite::Connection::open(&f.db_path).unwrap();
        conn.execute(
            "UPDATE vault_utxos SET amount_atomic = ?1",
            rusqlite::params![(UTXO_VALUE + 1).to_le_bytes().to_vec()],
        )
        .unwrap();
    }
    let err = sign(&f, 0, 0, &f.intent, &f.unsigned_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::IntegrityHalted { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0, "nothing may be signed after drift");

    let db = Db::open(&f.db_path).unwrap();
    assert_eq!(
        db.get_withdrawal(INDEX).unwrap().unwrap().state,
        WithdrawalState::IntegrityHalted,
        "the signer halts the anomaly rather than merely declining"
    );
}

#[tokio::test]
async fn a_disappeared_utxo_halts_rather_than_signing() {
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    {
        let conn = rusqlite::Connection::open(&f.db_path).unwrap();
        conn.execute("DELETE FROM vault_utxos", []).unwrap();
    }
    let err = sign(&f, 0, 0, &f.intent, &f.unsigned_hex)
        .await
        .unwrap_err();
    assert!(
        matches!(err, PayoutRefusal::IntegrityHalted { .. }),
        "{err:?}"
    );
    assert_eq!(f.signer.calls(), 0);
}

// ---------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------

#[test]
fn a_vault_index_outside_the_signer_set_is_refused_at_construction() {
    // ADR-0017 E1: fail closed rather than run with a mapping that could
    // route a signing request to the wrong key.
    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    assert!(PayoutView::new(f.cfg.clone(), 3, RecordingSigner::default()).is_err());
    assert!(PayoutView::new(f.cfg.clone(), 2, RecordingSigner::default()).is_ok());
}

#[test]
fn a_signer_must_prove_it_holds_the_key_at_its_configured_position() {
    // The strong half of E1: configuration says "you are signer 1"; the key
    // on disk must actually be signer 1's key.
    let (vault, _) = InProcessPayoutCollector::deterministic_test_vault(3, 2);
    // Round-trip a known-good key through the vault's own check.
    for i in 0..3u8 {
        let derived = libsecp256k1::PublicKey::from_secret_key(&deterministic_secret(i))
            .serialize_compressed();
        assert_eq!(
            vault.signer_pubkeys[i as usize], derived,
            "position {i} must hold the key the test derives"
        );
    }
}

// ---------------------------------------------------------------------
// The audit record (ADR-0014 §13.3)
// ---------------------------------------------------------------------

/// A granted payout signature must leave a record.
///
/// Added in Phase 7l after mutation testing found the payout grant's audit
/// call site entirely uncovered: deleting it broke nothing, because the
/// audit suite exercised only the mint path. The fixture lives here, so the
/// test does too.
#[tokio::test]
async fn granting_a_payout_signature_leaves_a_record() {
    use glc_relayer::p2p::service::pb::PayoutSignRequest;
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

    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let service = SignerService::new(solana_sdk::signature::Keypair::new(), FreshView)
        .with_payout_arm(view(&f, 0), Db::open(&f.db_path).unwrap());

    let (result, grants) = common::capture_grants_async(service.handle_payout(PayoutSignRequest {
        request_id: vec![1],
        epoch: 0,
        withdrawal_index: INDEX as u64,
        quorum_attempt: 0,
        canonical_intent: f.intent.clone(),
        unsigned_tx_hex: f.unsigned_hex.clone(),
        expiry_unix: glc_relayer::p2p::service::now_unix() + 60,
        proposer_index: 0,
    }))
    .await;

    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(grants.len(), 1, "exactly one record per granted payout");
    assert_eq!(grants[0].get("action"), Some("payout"));
    let id = grants[0].get("identity").unwrap();
    assert!(
        id.contains(&INDEX.to_string()) && id.contains("attempt 0"),
        "the record must name the withdrawal AND the quorum attempt: {id}"
    );
}

/// A refused payout must not be recorded as a grant.
#[tokio::test]
async fn a_refused_payout_produces_no_grant_record() {
    use glc_relayer::p2p::service::pb::PayoutSignRequest;
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

    let f = fixture(QUORUM, 0, WithdrawalState::Signing);
    let service = SignerService::new(solana_sdk::signature::Keypair::new(), FreshView)
        .with_payout_arm(view(&f, 0), Db::open(&f.db_path).unwrap());

    let (result, grants) = common::capture_grants_async(service.handle_payout(PayoutSignRequest {
        request_id: vec![1],
        epoch: 0,
        withdrawal_index: INDEX as u64,
        quorum_attempt: 0,
        // Not the intent this validator recomputes.
        canonical_intent: vec![0xFF; 32],
        unsigned_tx_hex: f.unsigned_hex.clone(),
        expiry_unix: glc_relayer::p2p::service::now_unix() + 60,
        proposer_index: 0,
    }))
    .await;

    assert!(result.is_err());
    assert!(
        grants.is_empty(),
        "a refusal must never appear as an authorisation: {grants:?}"
    );
}
