//! Mock-RPC integration tests for the Phase 6 withdrawal executor
//! (ADR-0013).
//!
//! A real SQLite *file* is used throughout (never `:memory:`) because
//! several tests need a second, independent connection to mutate state out
//! from under the executor, or to reopen the database as a restarted
//! process would.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use glc_relayer::glc::db::{Db, DbError};
use glc_relayer::glc::rpc::{BroadcastOutcome, RpcError};
use glc_relayer::glc::withdrawal_db::{NewWithdrawalRequest, ObservedUtxo, WithdrawalState};
use glc_relayer::withdrawal::address::{encode_p2pkh, p2pkh_script_hex};
use glc_relayer::withdrawal::builder::{DecodedInput, DecodedOutput, DecodedTx};
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::executor::{PayoutRpc, TxStatus, WithdrawalExecutor};

const DEST: [u8; 20] = [0xAA; 20];

/// The real 2-of-3 vault `createmultisig` produced on a regtest node during
/// Phase 7b verification (ADR-0015). Using the genuine script keeps these
/// tests honest about the address and script shapes the executor must emit.
const REDEEM: &str = "5221028e7147e643d67093dc8ca6a8fb888f1a452dddc62de991c7ed72080d65a421e42102f1c88ca7176c3ffee952ee6fae697991b257b6d53c3bc88e81cfe99adbcdbee5210256220bb7865197a40c4590ac80f12ef18e9063eac2eff92c4476ec27034042f953ae";
const VAULT_ADDR: &str = "QY9YcpypWD91BEZ37TjNHYoqrquhcnVBYV";

fn vault() -> glc_relayer::withdrawal::vault::MultisigVault {
    glc_relayer::withdrawal::vault::MultisigVault::from_redeem_script_hex(REDEEM).unwrap()
}

// ---------------------------------------------------------------------
// MockPayoutRpc
// ---------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    utxos: Vec<ObservedUtxo>,
    /// txid_hex -> status. Absent means "node has never seen it".
    chain: HashMap<String, TxStatus>,
    orphaned_blocks: Vec<String>,
    sign_calls: u32,
    send_calls: u32,
    sent_hexes: Vec<String>,
    /// Forces `signrawtransaction` to report `complete: false`.
    sign_incomplete: bool,
    /// Forces the next N `sendrawtransaction` calls to report -25.
    send_missing_inputs: u32,
    /// Makes `create_raw_transaction` emit a tampered transaction.
    tamper: Option<Tamper>,
}

#[derive(Clone, Copy, Debug)]
enum Tamper {
    WrongDestAmount,
    RedirectDest,
    ExtraOutput,
    DropChange,
    AlterOutputsWhenSigning,
}

#[derive(Clone, Default)]
struct MockPayoutRpc(Arc<Mutex<MockState>>);

impl MockPayoutRpc {
    fn new() -> Self {
        MockPayoutRpc::default()
    }
    fn set_utxos(&self, u: Vec<ObservedUtxo>) {
        self.0.lock().unwrap().utxos = u;
    }
    fn sign_calls(&self) -> u32 {
        self.0.lock().unwrap().sign_calls
    }
    fn send_calls(&self) -> u32 {
        self.0.lock().unwrap().send_calls
    }
    fn sent_hexes(&self) -> Vec<String> {
        self.0.lock().unwrap().sent_hexes.clone()
    }
    fn set_tamper(&self, t: Tamper) {
        self.0.lock().unwrap().tamper = Some(t);
    }
    fn set_sign_incomplete(&self) {
        self.0.lock().unwrap().sign_incomplete = true;
    }
    fn set_send_missing_inputs(&self, n: u32) {
        self.0.lock().unwrap().send_missing_inputs = n;
    }
    /// Puts a broadcast transaction into a block at `confirmations`.
    fn confirm(&self, txid_hex: &str, confirmations: i64, block: &str) {
        self.0.lock().unwrap().chain.insert(
            txid_hex.to_string(),
            TxStatus {
                confirmations,
                block_hash_hex: Some(block.to_string()),
                block_height: Some(100),
            },
        );
    }
    fn orphan_block(&self, block: &str) {
        self.0
            .lock()
            .unwrap()
            .orphaned_blocks
            .push(block.to_string());
    }
    fn forget_transaction(&self, txid_hex: &str) {
        self.0.lock().unwrap().chain.remove(txid_hex);
    }
    fn known_txids(&self) -> Vec<String> {
        self.0.lock().unwrap().chain.keys().cloned().collect()
    }
}

/// Deterministic fake txid derived from the transaction hex, so the same
/// bytes always produce the same txid — exactly like a real chain.
fn fake_txid_hex(hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(hex.as_bytes());
    use std::fmt::Write;
    d.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

impl PayoutRpc for MockPayoutRpc {
    async fn list_unspent(
        &self,
        _min_conf: i64,
        _addresses: &[String],
    ) -> Result<Vec<ObservedUtxo>, RpcError> {
        Ok(self.0.lock().unwrap().utxos.clone())
    }

    async fn create_raw_transaction(
        &self,
        inputs: &[(String, i64)],
        outputs: &[(String, u64)],
    ) -> Result<String, RpcError> {
        let tamper = self.0.lock().unwrap().tamper;
        let mut outs: Vec<(u64, String)> = outputs
            .iter()
            .map(|(addr, v)| {
                // Destination is P2PKH; change returns to the P2SH vault.
                let script = match glc_relayer::withdrawal::address::decode_p2pkh_hash160(addr) {
                    Ok(h) => p2pkh_script_hex(&h),
                    Err(_) => vault().script_pubkey_hex(),
                };
                (*v, script)
            })
            .collect();
        match tamper {
            Some(Tamper::WrongDestAmount) => outs[0].0 += 1,
            Some(Tamper::RedirectDest) => outs[0].1 = p2pkh_script_hex(&[0xCC; 20]),
            Some(Tamper::ExtraOutput) => outs.push((1, p2pkh_script_hex(&[0xCC; 20]))),
            Some(Tamper::DropChange) => {
                if outs.len() > 1 {
                    outs.pop();
                }
            }
            _ => {}
        }
        // Encode the whole shape into the "hex" so decode is exact.
        let body: Vec<String> = inputs
            .iter()
            .map(|(t, v)| format!("i:{t}:{v}"))
            .chain(outs.iter().map(|(v, s)| format!("o:{v}:{s}")))
            .collect();
        Ok(format!("RAW|{}", body.join("|")))
    }

    async fn decode_raw_transaction(&self, hex: &str) -> Result<DecodedTx, RpcError> {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for part in hex
            .trim_start_matches("RAW|")
            .trim_start_matches("SIGNED|")
            .split('|')
        {
            if let Some(rest) = part.strip_prefix("i:") {
                let (t, v) = rest.rsplit_once(':').unwrap();
                inputs.push(DecodedInput {
                    txid_hex: t.to_string(),
                    vout: v.parse().unwrap(),
                });
            } else if let Some(rest) = part.strip_prefix("o:") {
                let (v, s) = rest.split_once(':').unwrap();
                outputs.push(DecodedOutput {
                    value_atomic: v.parse().unwrap(),
                    script_pubkey_hex: s.to_string(),
                });
            }
        }
        Ok(DecodedTx {
            txid_hex: fake_txid_hex(hex.trim_start_matches("SIGNED|")),
            inputs,
            outputs,
        })
    }

    async fn sign_raw_transaction(
        &self,
        hex: &str,
        _prevtxs: &[glc_relayer::glc::rpc::PrevTx],
    ) -> Result<(String, bool), RpcError> {
        let (incomplete, tamper) = {
            let mut s = self.0.lock().unwrap();
            s.sign_calls += 1;
            (s.sign_incomplete, s.tamper)
        };
        if incomplete {
            return Ok((hex.to_string(), false));
        }
        let mut signed = format!("SIGNED|{}", hex.trim_start_matches("RAW|"));
        if matches!(tamper, Some(Tamper::AlterOutputsWhenSigning)) {
            // Bump the first output's value during "signing".
            if let Some(pos) = signed.find("|o:") {
                let rest = &signed[pos + 3..];
                let (v, tail) = rest.split_once(':').unwrap();
                let bumped: u64 = v.parse::<u64>().unwrap() + 1;
                signed = format!("{}|o:{}:{}", &signed[..pos], bumped, tail);
            }
        }
        Ok((signed, true))
    }

    async fn send_raw_transaction(&self, hex: &str) -> Result<BroadcastOutcome, RpcError> {
        let mut s = self.0.lock().unwrap();
        s.send_calls += 1;
        s.sent_hexes.push(hex.to_string());
        if s.send_missing_inputs > 0 {
            s.send_missing_inputs -= 1;
            return Ok(BroadcastOutcome::MissingInputs);
        }
        let txid = fake_txid_hex(hex.trim_start_matches("SIGNED|"));
        if let Some(st) = s.chain.get(&txid) {
            if st.confirmations > 0 {
                return Ok(BroadcastOutcome::AlreadyInChain);
            }
        }
        s.chain.entry(txid.clone()).or_insert(TxStatus {
            confirmations: 0,
            block_hash_hex: None,
            block_height: None,
        });
        Ok(BroadcastOutcome::Accepted { txid })
    }

    async fn transaction_confirmations(
        &self,
        txid_hex: &str,
    ) -> Result<Option<TxStatus>, RpcError> {
        Ok(self.0.lock().unwrap().chain.get(txid_hex).cloned())
    }

    async fn block_on_main_chain(&self, block_hash_hex: &str) -> Result<bool, RpcError> {
        Ok(!self
            .0
            .lock()
            .unwrap()
            .orphaned_blocks
            .iter()
            .any(|b| b == block_hash_hex))
    }
}

// ---------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------

const RATE: u64 = 10_000;
const DUST: u64 = 5_400;

fn config() -> WithdrawalConfig {
    WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: REDEEM.into(),
        vault_address: VAULT_ADDR.into(),
        change_address: VAULT_ADDR.into(),
        fee_rate_per_kb: RATE,
        dust_threshold_atomic: DUST,
        vault_min_confirmations: 1,
        confirmation_depth: 3,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 1_000,
    })
    .unwrap()
}

fn utxo(seed: u8, vout: i64, amount: u64) -> ObservedUtxo {
    ObservedUtxo {
        txid: [seed; 32],
        vout,
        amount_atomic: amount,
        script_pubkey_hex: vault().script_pubkey_hex(),
        confirmations: 10,
    }
}

fn withdrawal(index: i64, amount: u64) -> NewWithdrawalRequest {
    NewWithdrawalRequest {
        withdrawal_index: index,
        pda: [index as u8; 32],
        amount_atomic: amount,
        requester: [0x11; 32],
        glc_address: encode_p2pkh(&DEST),
        glc_address_hash160: DEST,
        requested_at_slot: 10,
        protocol_version: 1,
        observed_at: 0,
        observed_at_slot: 10,
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    rpc: MockPayoutRpc,
}

impl Harness {
    fn new(utxos: Vec<ObservedUtxo>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayer.sqlite3");
        Db::open(&db_path).unwrap();
        let rpc = MockPayoutRpc::new();
        rpc.set_utxos(utxos);
        Harness {
            _dir: dir,
            db_path,
            rpc,
        }
    }
    /// A brand-new executor over a brand-new connection: exactly what a
    /// process restart produces.
    fn executor(&self) -> WithdrawalExecutor<MockPayoutRpc> {
        WithdrawalExecutor::new(Db::open(&self.db_path).unwrap(), self.rpc.clone(), config())
    }
    fn db(&self) -> Db {
        Db::open(&self.db_path).unwrap()
    }
    fn state(&self, index: i64) -> WithdrawalState {
        self.db().get_withdrawal(index).unwrap().unwrap().state
    }
    fn txid(&self, index: i64) -> Option<String> {
        self.db()
            .get_payout(index)
            .unwrap()
            .and_then(|p| p.txid_hex)
    }
    /// Row counts via an independent connection — integration tests cannot
    /// reach `Db`'s crate-private raw handle.
    fn count(&self, sql: &str) -> i64 {
        rusqlite::Connection::open(&self.db_path)
            .unwrap()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    }
}

fn mutate(db_path: &Path, sql: &str, p: &[&dyn rusqlite::ToSql]) {
    rusqlite::Connection::open(db_path)
        .unwrap()
        .execute(sql, p)
        .unwrap();
}

/// Drives a withdrawal to `Broadcast` (built, signed, sent).
async fn drive_to_broadcast(h: &Harness, index: i64, amount: u64) {
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(index, amount)]).unwrap();
    e.tick().await.unwrap(); // Observed -> Validated -> Building -> Signing -> Broadcast
}

// ---------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------

#[tokio::test]
async fn full_pipeline_observed_to_completed() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    assert_eq!(h.state(1), WithdrawalState::Confirming);
    let txid = h.txid(1).expect("txid durable before broadcast");
    assert_eq!(h.rpc.send_calls(), 1);

    // Not yet deep enough.
    h.rpc.confirm(&txid, 1, "block-a");
    h.executor().tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Confirming);

    // Reaches the configured depth.
    h.rpc.confirm(&txid, 3, "block-a");
    let r = h.executor().tick().await.unwrap();
    assert_eq!(r.completed, 1);
    assert_eq!(h.state(1), WithdrawalState::Completed);

    let p = h.db().get_payout(1).unwrap().unwrap();
    assert_eq!(
        p.payout_atomic, 1_000_000,
        "D3: the user receives exactly the burned amount"
    );
    assert!(p.fee_atomic > 0, "the vault paid a fee");
    assert_eq!(
        p.payout_atomic + p.fee_atomic + p.change_atomic,
        5_000_000,
        "value is conserved"
    );
    let spent = h.count("SELECT COUNT(*) FROM vault_utxos WHERE state='Spent'");
    assert_eq!(spent, 1);
}

#[tokio::test]
async fn payout_equals_burned_amount_exactly_for_many_amounts() {
    for amount in [10_000u64, 123_456, 1_000_000, 4_000_000] {
        let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
        drive_to_broadcast(&h, 1, amount).await;
        let p = h.db().get_payout(1).unwrap().unwrap();
        assert_eq!(p.payout_atomic, amount, "vault absorbs the fee (D3)");
    }
}

// ---------------------------------------------------------------------
// Funds
// ---------------------------------------------------------------------

#[tokio::test]
async fn insufficient_funds_park_in_awaiting_funds_then_proceed_when_funded() {
    let h = Harness::new(vec![utxo(1, 0, 50_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::AwaitingFunds);
    assert_eq!(h.rpc.sign_calls(), 0, "nothing is signed while underfunded");

    h.rpc
        .set_utxos(vec![utxo(1, 0, 50_000), utxo(2, 0, 5_000_000)]);
    h.executor().tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Confirming);
}

#[tokio::test]
async fn a_below_dust_withdrawal_fails_permanently_and_is_never_signed() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, DUST - 1)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Failed);
    assert_eq!(h.rpc.sign_calls(), 0);
    assert_eq!(h.rpc.send_calls(), 0);
}

// ---------------------------------------------------------------------
// Output verification before signing
// ---------------------------------------------------------------------

#[tokio::test]
async fn every_output_tamper_is_caught_before_signing() {
    for t in [
        Tamper::WrongDestAmount,
        Tamper::RedirectDest,
        Tamper::ExtraOutput,
        Tamper::DropChange,
    ] {
        let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
        h.rpc.set_tamper(t);
        let mut e = h.executor();
        e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
        e.tick().await.unwrap();
        assert_eq!(
            h.state(1),
            WithdrawalState::IntegrityHalted,
            "{t:?} must halt before signing"
        );
        assert_eq!(h.rpc.sign_calls(), 0, "{t:?}: nothing may be signed");
        assert_eq!(h.rpc.send_calls(), 0, "{t:?}: nothing may be broadcast");
    }
}

#[tokio::test]
async fn outputs_altered_during_signing_are_detected_and_never_broadcast() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    h.rpc.set_tamper(Tamper::AlterOutputsWhenSigning);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
    assert_eq!(
        h.rpc.send_calls(),
        0,
        "a mutated signed tx must never be sent"
    );
}

#[tokio::test]
async fn an_incomplete_signature_halts_rather_than_broadcasting() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    h.rpc.set_sign_incomplete();
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
    assert_eq!(h.rpc.send_calls(), 0);
}

// ---------------------------------------------------------------------
// Pre-signing guards (owner requirement) — mutation proofs
// ---------------------------------------------------------------------

/// Drives to `Signing` without signing, so a guard can be exercised.
async fn drive_to_signing(h: &Harness, index: i64, amount: u64) {
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(index, amount)]).unwrap();
    // Build only: tamper-free build, then stop before sign by using a
    // separate executor whose sign step we trigger manually below.
    e.tick().await.unwrap();
}

#[tokio::test]
async fn guard_refuses_to_sign_twice_even_when_forced() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_signing(&h, 1, 1_000_000).await;
    let signs_after_first = h.rpc.sign_calls();
    assert_eq!(signs_after_first, 1);

    // Force the row back to Signing as a corrupted/stale state would.
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET state='Signing' WHERE withdrawal_index=1",
        &[],
    );
    h.executor().tick().await.unwrap();

    assert_eq!(
        h.rpc.sign_calls(),
        signs_after_first,
        "the already-signed guard must prevent a second signature"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

#[tokio::test]
async fn guard_refuses_when_the_reservation_was_stolen_by_another_withdrawal() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000), withdrawal(2, 10_000)])
        .unwrap();
    // Build #1 only, by hand, then steal its reservation before signing.
    e.tick().await.unwrap();
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET state='Signing' WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET signed_tx_hex=NULL, txid=NULL, txid_hex=NULL WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE vault_utxos SET reserved_by=2 WHERE reserved_by=1",
        &[],
    );
    let before = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(
        h.rpc.sign_calls(),
        before,
        "must not sign a stolen reservation"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

#[tokio::test]
async fn guard_refuses_when_a_reserved_utxo_disappeared() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET state='Signing' WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET signed_tx_hex=NULL, txid=NULL, txid_hex=NULL WHERE withdrawal_index=1",
        &[],
    );
    mutate(&h.db_path, "DELETE FROM vault_utxos", &[]);
    let before = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(h.rpc.sign_calls(), before);
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

#[tokio::test]
async fn guard_refuses_when_the_committed_amount_drifted() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET state='Signing' WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET signed_tx_hex=NULL, txid=NULL, txid_hex=NULL WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET amount_atomic=?1 WHERE withdrawal_index=1",
        &[&9_999_999u64.to_le_bytes().to_vec()],
    );
    let before = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(
        h.rpc.sign_calls(),
        before,
        "a drifted amount must never be signed"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

// ---------------------------------------------------------------------
// Broadcast / restart / reorg
// ---------------------------------------------------------------------

#[tokio::test]
async fn restart_before_confirmation_rebroadcasts_identical_bytes_and_never_repays() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    let first = h.rpc.sent_hexes()[0].clone();
    let txid = h.txid(1).unwrap();
    let signs = h.rpc.sign_calls();

    // Restart repeatedly while still unconfirmed: each iteration is a brand
    // new executor over a brand new connection, exactly as a crash-restart.
    for _ in 0..4 {
        h.executor().tick().await.unwrap();
    }

    // The safety properties, not the send count: whatever was sent was the
    // identical byte string, the payout was never re-signed or rebuilt, and
    // exactly one transaction exists on the chain.
    for s in h.rpc.sent_hexes() {
        assert_eq!(s, first, "only ever the IDENTICAL byte string is resent");
    }
    assert_eq!(h.rpc.sign_calls(), signs, "restart must never re-sign");
    assert_eq!(h.txid(1).unwrap(), txid, "the txid never changes");
    assert_eq!(
        h.rpc.known_txids().len(),
        1,
        "exactly one transaction exists — no second payment"
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM withdrawal_payouts"), 1);
}

#[tokio::test]
async fn a_dropped_transaction_is_rebroadcast_not_rebuilt() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    let txid = h.txid(1).unwrap();
    let original = h.rpc.sent_hexes()[0].clone();

    let signs = h.rpc.sign_calls();
    h.rpc.forget_transaction(&txid); // dropped from mempool

    // One tick detects the drop and self-heals: Confirming -> Orphaned ->
    // rebroadcast(identical bytes) -> Broadcast -> Confirming.
    h.executor().tick().await.unwrap();

    assert_eq!(
        h.state(1),
        WithdrawalState::Confirming,
        "a dropped transaction is recovered within the same tick"
    );
    assert_eq!(
        h.txid(1).unwrap(),
        txid,
        "the txid never changes — the payout is never rebuilt"
    );
    assert_eq!(h.rpc.sign_calls(), signs, "recovery never re-signs");
    assert!(
        h.rpc.sent_hexes().iter().all(|s| *s == original),
        "only the identical byte string is ever resent"
    );
    // The recovery is visible in the audit trail.
    assert!(
        h.count(
            "SELECT COUNT(*) FROM withdrawal_state_log
             WHERE withdrawal_index=1 AND to_state='Orphaned'"
        ) >= 1,
        "the orphaning is recorded"
    );
}

#[tokio::test]
async fn a_reorged_out_payout_returns_to_orphaned_then_reconfirms() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    let txid = h.txid(1).unwrap();

    h.rpc.confirm(&txid, 2, "block-x");
    h.executor().tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Confirming);

    // The block containing it is orphaned.
    h.rpc.orphan_block("block-x");
    h.executor().tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Orphaned);

    // Re-mined into a good block at depth.
    h.rpc.confirm(&txid, 5, "block-y");
    h.executor().tick().await.unwrap(); // Orphaned -> rebroadcast -> Confirming
    h.executor().tick().await.unwrap(); // -> Completed
    assert_eq!(h.state(1), WithdrawalState::Completed);
    assert_eq!(
        h.txid(1).unwrap(),
        txid,
        "the same transaction completed; nothing was rebuilt"
    );
}

#[tokio::test]
async fn already_in_chain_on_rebroadcast_is_treated_as_success() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    let txid = h.txid(1).unwrap();
    h.rpc.confirm(&txid, 1, "block-a"); // now mined; resend yields -27
    h.executor().tick().await.unwrap();
    assert_ne!(
        h.state(1),
        WithdrawalState::IntegrityHalted,
        "-27 is success, not a failure"
    );
    h.rpc.confirm(&txid, 9, "block-a");
    h.executor().tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::Completed);
}

#[tokio::test]
async fn missing_inputs_on_broadcast_triggers_reconciliation_not_a_rebuild() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    let txid = h.txid(1).unwrap();
    h.rpc.forget_transaction(&txid);
    h.rpc.set_send_missing_inputs(5);

    h.executor().tick().await.unwrap();
    h.executor().tick().await.unwrap();

    assert_eq!(
        h.txid(1).unwrap(),
        txid,
        "a conflict must never cause a rebuild with different inputs"
    );
    let payouts = h.count("SELECT COUNT(*) FROM withdrawal_payouts");
    assert_eq!(payouts, 1, "still exactly one payout");
}

// ---------------------------------------------------------------------
// Structural never-double-pay
// ---------------------------------------------------------------------

#[tokio::test]
async fn two_withdrawals_never_share_an_outpoint() {
    // Only one UTXO, two withdrawals that each need it.
    let h = Harness::new(vec![utxo(1, 0, 3_000_000)]);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000), withdrawal(2, 1_000_000)])
        .unwrap();
    e.tick().await.unwrap();

    let inputs = h.count("SELECT COUNT(*) FROM withdrawal_payout_inputs");
    let distinct =
        h.count("SELECT COUNT(DISTINCT txid || ':' || vout) FROM withdrawal_payout_inputs");
    assert_eq!(inputs, distinct, "no outpoint is committed twice");

    // The second withdrawal could not be funded and must be waiting.
    assert_eq!(h.state(2), WithdrawalState::AwaitingFunds);
}

#[tokio::test]
async fn duplicate_discovery_is_idempotent() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    let mut e = h.executor();
    assert_eq!(e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap(), 1);
    assert_eq!(e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap(), 0);
    e.tick().await.unwrap();
    // Re-discovering after the pipeline advanced must not reset it.
    assert_eq!(e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap(), 0);
    assert_eq!(h.state(1), WithdrawalState::Confirming);
    assert_eq!(h.count("SELECT COUNT(*) FROM withdrawal_payouts"), 1);
}

// ---------------------------------------------------------------------
// IntegrityHalted terminality and operator recovery
// ---------------------------------------------------------------------

#[tokio::test]
async fn integrity_halted_is_terminal_across_ticks_and_restarts() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    h.rpc.set_tamper(Tamper::RedirectDest);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
    let signs = h.rpc.sign_calls();
    let sends = h.rpc.send_calls();

    for _ in 0..5 {
        h.executor().tick().await.unwrap(); // fresh executor each time = restart
    }
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
    assert_eq!(h.rpc.sign_calls(), signs, "never signed after halting");
    assert_eq!(h.rpc.send_calls(), sends, "never broadcast after halting");
}

#[tokio::test]
async fn operator_recovery_is_the_only_exit_and_cannot_claim_a_payment() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    h.rpc.set_tamper(Tamper::RedirectDest);
    let mut e = h.executor();
    e.ingest_discovered(&[withdrawal(1, 1_000_000)]).unwrap();
    e.tick().await.unwrap();
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);

    let mut db = h.db();
    assert!(matches!(
        db.operator_clear_withdrawal_halt(1, WithdrawalState::Failed, "   ", 100),
        Err(DbError::WithdrawalOperatorNoteRequired(1))
    ));
    for bad in [
        WithdrawalState::Completed,
        WithdrawalState::Broadcast,
        WithdrawalState::Confirming,
    ] {
        assert!(matches!(
            db.operator_clear_withdrawal_halt(1, bad, "force", 100),
            Err(DbError::InvalidWithdrawalRecoveryTarget { .. })
        ));
    }
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);

    db.operator_clear_withdrawal_halt(1, WithdrawalState::Failed, "investigated: node bug", 200)
        .unwrap();
    assert_eq!(h.state(1), WithdrawalState::Failed);

    let halts = h.count(
        "SELECT COUNT(*) FROM withdrawal_state_log WHERE withdrawal_index=1 AND to_state='IntegrityHalted'",
    );
    assert_eq!(halts, 1, "the original anomaly record survives recovery");
}

/// Puts a built payout back into `Signing` with its signature cleared, so a
/// specific pre-signing guard can be isolated.
fn rewind_to_signing(h: &Harness) {
    mutate(
        &h.db_path,
        "UPDATE withdrawal_requests SET state='Signing' WHERE withdrawal_index=1",
        &[],
    );
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET signed_tx_hex=NULL, txid=NULL, txid_hex=NULL WHERE withdrawal_index=1",
        &[],
    );
}

#[tokio::test]
async fn guard_refuses_when_only_the_fee_drifted() {
    // Isolates the commitment recomputation: the fee is not covered by the
    // payout-equals-amount check, so ONLY the recomputed commitment catches
    // this.
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    rewind_to_signing(&h);
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET fee_atomic=?1 WHERE withdrawal_index=1",
        &[&7_777u64.to_le_bytes().to_vec()],
    );
    let signs = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(
        h.rpc.sign_calls(),
        signs,
        "a drifted fee must never be signed"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

#[tokio::test]
async fn guard_refuses_when_a_payout_is_already_confirmed() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    rewind_to_signing(&h);
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET confirmations=4 WHERE withdrawal_index=1",
        &[],
    );
    let signs = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(
        h.rpc.sign_calls(),
        signs,
        "an already-confirmed payout must never be re-signed"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}

#[tokio::test]
async fn guard_refuses_when_a_payout_is_already_completed() {
    let h = Harness::new(vec![utxo(1, 0, 5_000_000)]);
    drive_to_broadcast(&h, 1, 1_000_000).await;
    rewind_to_signing(&h);
    mutate(
        &h.db_path,
        "UPDATE withdrawal_payouts SET completed_at=123 WHERE withdrawal_index=1",
        &[],
    );
    let signs = h.rpc.sign_calls();
    h.executor().tick().await.unwrap();
    assert_eq!(
        h.rpc.sign_calls(),
        signs,
        "a completed payout must never be re-signed"
    );
    assert_eq!(h.state(1), WithdrawalState::IntegrityHalted);
}
