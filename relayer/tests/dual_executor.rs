//! TEMPORARY measurement harness for the Phase 7g design (ADR-0014 §10, D8).
//!
//! Two independent executors — separate databases, one shared Goldcoin
//! regtest node — driven with **staggered discovery**, to measure whether
//! and how often they build *different* payouts for the same withdrawal.
//!
//! # Why this is worth measuring rather than reasoning about
//!
//! ADR-0014 §10 assumed deterministic coin selection is enough for two
//! executors to agree. It is not, because `available_utxos` filters on
//! `state = 'Available'` — **local reservation state**. Two operators that
//! observe withdrawals in different orders reserve different UTXOs, and then
//! build genuinely different transactions from identical, deterministic
//! rules.
//!
//! Phase 7e's signer refuses anything that does not match what its own
//! executor built, so divergence is safe — it stalls rather than
//! mis-pays — but it is a liveness problem, and the design's answer should
//! rest on how bad it actually is.
//!
//! # Status: PERMANENT
//!
//! These began as the Phase 7g measurement harness and are kept because they
//! are the only tests that exercise two executors at once. `m1` and `m2`
//! record the behaviour that motivated ADR-0019 — run against the code as it
//! was, they FAIL — and `m3` is the regression guard for the fix.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use glc_relayer::glc::config::RpcConfigValidated;
use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::RpcClient;
use glc_relayer::glc::withdrawal_db::{NewWithdrawalRequest, WithdrawalState};
use glc_relayer::solana::epoch::EpochObservation;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::address::decode_p2pkh_hash160;
use glc_relayer::withdrawal::assignment::OperatorAssignment;
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::executor::WithdrawalExecutor;
use glc_relayer::withdrawal::federation::InProcessPayoutCollector;

fn goldcoind_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIND_BIN").map(PathBuf::from)
}
fn goldcoin_cli_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIN_CLI_BIN").map(PathBuf::from)
}

struct RegtestNode {
    child: Child,
    cli: PathBuf,
    datadir: tempfile::TempDir,
    rpc_port: u16,
    user: String,
    password: String,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl RegtestNode {
    fn start(goldcoind: &Path, cli: &Path) -> Self {
        let datadir = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let user = "glc_g_user".to_string();
        let password = format!("glc_g_pw_{}", std::process::id());
        let child = Command::new(goldcoind)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.path().display()))
            .arg("-daemon=0")
            .arg("-printtoconsole=0")
            .arg(format!("-rpcuser={user}"))
            .arg(format!("-rpcpassword={password}"))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={}", free_port()))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .arg("-fallbackfee=0.0001")
            .arg("-txindex=1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn goldcoind");
        let node = RegtestNode {
            child,
            cli: cli.to_path_buf(),
            datadir,
            rpc_port,
            user,
            password,
        };
        node.wait_ready();
        node
    }

    fn cli_cmd(&self) -> Command {
        let mut c = Command::new(&self.cli);
        c.arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.path().display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcuser={}", self.user))
            .arg(format!("-rpcpassword={}", self.password));
        c
    }

    fn cli(&self, args: &[&str]) -> String {
        let out = self.cli_cmd().args(args).output().expect("goldcoin-cli");
        assert!(
            out.status.success(),
            "goldcoin-cli {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let o = self.cli_cmd().args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    fn wait_ready(&self) {
        for _ in 0..120 {
            if self
                .cli_cmd()
                .arg("getblockcount")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        panic!("goldcoind never became ready");
    }

    fn rpc_config(&self) -> RpcConfigValidated {
        RpcConfigValidated {
            url: format!("http://127.0.0.1:{}", self.rpc_port),
            user: self.user.clone(),
            password: self.password.clone(),
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        }
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config(vault: &str, redeem: &str) -> WithdrawalConfig {
    WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: redeem.to_string(),
        vault_address: vault.to_string(),
        change_address: vault.to_string(),
        fee_rate_per_kb: 100_000,
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: 2,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 500,
    })
    .unwrap()
}

fn withdrawal(index: i64, amount: u64, dest: &str) -> NewWithdrawalRequest {
    NewWithdrawalRequest {
        withdrawal_index: index,
        pda: [index as u8; 32],
        amount_atomic: amount,
        requester: [0x11; 32],
        glc_address: dest.to_string(),
        glc_address_hash160: decode_p2pkh_hash160(dest).unwrap(),
        requested_at_slot: 1,
        protocol_version: 1,
        observed_at: now_unix(),
        observed_at_slot: 1,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One simulated operator: its own database, its own executor.
struct Operator {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    exec: WithdrawalExecutor<RealPayoutRpc, InProcessPayoutCollector>,
}

impl Operator {
    /// An operator that builds but can never sign: its collector holds no
    /// vault keys, so every payout stalls at `Signing` with an unsigned
    /// transaction persisted. Lets build divergence be measured WITHOUT
    /// either operator spending anything on the shared chain.
    fn build_only(node: &RegtestNode, cfg: &WithdrawalConfig) -> Self {
        Self::with_keys(node, cfg, &[], None)
    }

    fn new(node: &RegtestNode, cfg: &WithdrawalConfig, wifs: &[(u8, String)]) -> Self {
        Self::with_keys(node, cfg, wifs, None)
    }

    /// An operator that knows its place in a federation of `count`.
    fn assigned(
        node: &RegtestNode,
        cfg: &WithdrawalConfig,
        wifs: &[(u8, String)],
        index: usize,
        count: usize,
    ) -> Self {
        Self::with_keys(
            node,
            cfg,
            wifs,
            Some(OperatorAssignment::new(index, count, 3_600, 3_600).unwrap()),
        )
    }

    fn with_keys(
        node: &RegtestNode,
        cfg: &WithdrawalConfig,
        wifs: &[(u8, String)],
        assignment: Option<OperatorAssignment>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayer.sqlite3");
        Db::open(&db_path).unwrap();
        let collector =
            InProcessPayoutCollector::from_wifs(cfg.vault.clone(), wifs).expect("vault keys");

        let mut exec = WithdrawalExecutor::new(
            Db::open(&db_path).unwrap(),
            RealPayoutRpc::new(RpcClient::new(&node.rpc_config()).unwrap()),
            cfg.clone(),
            collector,
            std::sync::Arc::new(EpochObservation::seeded(1, now_unix())),
        );
        if let Some(a) = assignment {
            exec = exec.with_assignment(a);
        }
        Operator {
            _dir: dir,
            db_path,
            exec,
        }
    }

    fn db(&self) -> Db {
        Db::open(&self.db_path).unwrap()
    }

    /// The unsigned transaction this operator built for `index`, if any.
    fn unsigned(&self, index: i64) -> Option<String> {
        self.db()
            .get_payout(index)
            .unwrap()
            .map(|p| p.unsigned_tx_hex)
    }

    fn state(&self, index: i64) -> Option<WithdrawalState> {
        self.db().get_withdrawal(index).unwrap().map(|w| w.state)
    }
}

struct Fixture {
    node: RegtestNode,
    vault: String,
    redeem: String,
    wifs: Vec<(u8, String)>,
    dest: String,
}

/// A vault funded with `count` separate UTXOs of `each` GLC.
fn fixture(count: usize, each: &str) -> Fixture {
    let node = RegtestNode::start(&goldcoind_bin().unwrap(), &goldcoin_cli_bin().unwrap());
    let signers: Vec<String> = (0..3).map(|_| node.cli(&["getnewaddress"])).collect();
    let pubkeys: Vec<String> = signers
        .iter()
        .map(|a| {
            let v: serde_json::Value =
                serde_json::from_str(&node.cli(&["validateaddress", a])).unwrap();
            v["pubkey"].as_str().unwrap().to_string()
        })
        .collect();
    let ms: serde_json::Value = serde_json::from_str(&node.cli(&[
        "createmultisig",
        "2",
        &serde_json::to_string(&pubkeys).unwrap(),
    ]))
    .unwrap();
    let vault = ms["address"].as_str().unwrap().to_string();
    let redeem = ms["redeemScript"].as_str().unwrap().to_string();
    let _ = node.try_cli(&["importaddress", &vault, "vault", "false"]);
    let _ = node.try_cli(&["importaddress", &redeem, "vault-redeem", "false", "true"]);
    let wifs: Vec<(u8, String)> = signers
        .iter()
        .enumerate()
        .map(|(i, a)| (i as u8, node.cli(&["dumpprivkey", a])))
        .collect();

    let dest = node.cli(&["getnewaddress"]);
    let miner = node.cli(&["getnewaddress"]);
    node.cli(&["generatetoaddress", "130", &miner]);
    // Fund each UTXO in its own block, and lock it immediately so the
    // wallet does not consolidate the vault's own outputs.
    for _ in 0..count {
        node.cli(&["sendtoaddress", &vault, each]);
        node.cli(&["generatetoaddress", "1", &miner]);
        let listed = node.cli(&["listunspent", "1", "9999999", &format!("[\"{vault}\"]")]);
        let items: Vec<serde_json::Value> = serde_json::from_str::<serde_json::Value>(&listed)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|e| serde_json::json!({ "txid": e["txid"], "vout": e["vout"] }))
            .collect();
        if !items.is_empty() {
            node.cli(&[
                "lockunspent",
                "false",
                &serde_json::Value::Array(items).to_string(),
            ]);
        }
    }
    node.cli(&["lockunspent", "true"]);
    node.cli(&["generatetoaddress", "3", &miner]);

    Fixture {
        node,
        vault,
        redeem,
        wifs,
        dest,
    }
}

// ---------------------------------------------------------------------
// The measurements
// ---------------------------------------------------------------------

/// How much `txid` pays to `dest`, by DECODING the transaction.
///
/// `listunspent` is not usable here: the regtest wallet holds `dest` too and
/// will happily spend its outputs to fund later sends, so an unspent-balance
/// metric under-reports what was actually paid. An earlier version of this
/// harness made exactly that mistake and reported "no overpayment" for a run
/// that had in fact paid a withdrawal twice.
fn paid_to(node: &RegtestNode, txid: &str, dest: &str) -> u64 {
    let Some(j) = node.try_cli(&["getrawtransaction", txid, "1"]) else {
        return 0;
    };
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    if v.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0) < 1 {
        return 0;
    }
    v["vout"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| {
            o["scriptPubKey"]["addresses"]
                .as_array()
                .map(|a| a.iter().any(|x| x.as_str() == Some(dest)))
                .unwrap_or(false)
        })
        .map(|o| (o["value"].as_f64().unwrap() * 1e8).round() as u64)
        .sum()
}

#[tokio::test]
async fn m1_build_divergence_in_isolation() {
    // Neither operator can sign, so nothing is broadcast and the shared
    // chain never moves. Any difference is PURELY build divergence.
    let Some(_) = goldcoind_bin() else {
        eprintln!("GOLDCOIND_BIN unset — skipping");
        return;
    };
    let f = fixture(4, "40.0");
    let cfg = config(&f.vault, &f.redeem);

    println!("\n=== M1: build divergence, nothing broadcast ===");
    println!("4 x 40 GLC utxos; withdrawals 5 and 7 of 30 GLC each\n");

    let cases: [(&str, bool); 2] = [("same order", false), ("B sees 7 first", true)];
    for (label, stagger) in cases {
        let mut a = Operator::build_only(&f.node, &cfg);
        let mut b = Operator::build_only(&f.node, &cfg);
        let w5 = withdrawal(5, 30_00000000, &f.dest);
        let w7 = withdrawal(7, 30_00000000, &f.dest);

        a.exec.ingest_discovered(&[w5.clone(), w7.clone()]).unwrap();
        if stagger {
            b.exec.ingest_discovered(&[w7.clone()]).unwrap();
            b.exec.tick().await.unwrap();
            b.exec.ingest_discovered(&[w5.clone()]).unwrap();
        } else {
            b.exec.ingest_discovered(&[w5.clone(), w7.clone()]).unwrap();
        }
        a.exec.tick().await.unwrap();
        b.exec.tick().await.unwrap();

        let built = |o: &Operator, i: i64| o.unsigned(i).is_some();
        println!(
            "{label:16} built: A5={} B5={} A7={} B7={}",
            built(&a, 5),
            built(&b, 5),
            built(&a, 7),
            built(&b, 7)
        );
        for i in [5i64, 7] {
            match (a.unsigned(i), b.unsigned(i)) {
                (Some(x), Some(y)) if x == y => println!("  w{i}: AGREE"),
                (Some(_), Some(_)) => println!("  w{i}: *** DIVERGED ***"),
                (x, y) => println!(
                    "  w{i}: not comparable (A built={}, B built={})",
                    x.is_some(),
                    y.is_some()
                ),
            }
        }
        for i in [5i64, 7] {
            for op in [&a, &b] {
                assert!(
                    op.db()
                        .get_payout(i)
                        .unwrap()
                        .and_then(|p| p.txid_hex)
                        .is_none(),
                    "nothing may be broadcast in the build-only measurement"
                );
            }
        }
    }
}

/// The Phase 7g fix, measured against the exact scenario that broke.
///
/// Builder-authoritative reservation (ADR-0019 D3): only the designated
/// operator builds, so nobody reserves speculatively and the cause of §2.1's
/// divergence is gone rather than mitigated.
#[tokio::test]
async fn m3_builder_authoritative_removes_the_divergence() {
    let Some(_) = goldcoind_bin() else {
        eprintln!("GOLDCOIND_BIN unset — skipping");
        return;
    };
    let f = fixture(4, "40.0");
    let cfg = config(&f.vault, &f.redeem);

    println!("\n=== M3: with builder-authoritative assignment ===");
    println!("withdrawal 5 -> operator 1;  withdrawal 7 -> operator 1  (index mod 2)\n");

    // Two operators, 0 and 1, with a long failover window so neither takes
    // over the other's work during the measurement.
    let mut a = Operator::with_keys(
        &f.node,
        &cfg,
        &[],
        Some(OperatorAssignment::new(0, 2, 3_600, 3_600).unwrap()),
    );
    let mut b = Operator::with_keys(
        &f.node,
        &cfg,
        &[],
        Some(OperatorAssignment::new(1, 2, 3_600, 3_600).unwrap()),
    );
    let w5 = withdrawal(5, 30_00000000, &f.dest);
    let w7 = withdrawal(7, 30_00000000, &f.dest);

    // The SAME staggered discovery that diverged in M1.
    a.exec.ingest_discovered(&[w5.clone(), w7.clone()]).unwrap();
    b.exec.ingest_discovered(&[w7.clone()]).unwrap();
    b.exec.tick().await.unwrap();
    b.exec.ingest_discovered(&[w5.clone()]).unwrap();
    a.exec.tick().await.unwrap();
    b.exec.tick().await.unwrap();

    for i in [5i64, 7] {
        let designated = (i as u64 % 2) as usize;
        let (builder, passive) = if designated == 0 { (&a, &b) } else { (&b, &a) };
        println!(
            "  w{i}: designated=operator{designated}  builder_built={}  passive_built={}",
            builder.unsigned(i).is_some(),
            passive.unsigned(i).is_some()
        );
        assert!(
            builder.unsigned(i).is_some(),
            "w{i}: the designated builder must build"
        );
        assert!(
            passive.unsigned(i).is_none(),
            "w{i}: a PASSIVE operator must not build, and so must not reserve — that \
             speculative reservation is what caused the divergence measured in M1"
        );
    }
    println!("\n  no operator built work assigned to another => no competing reservations");
}

/// The §2.2 scenario replayed WITH the Phase 7g guards. Each withdrawal
/// must now be paid exactly once (ADR-0019 §4.2).
#[tokio::test]
async fn m4_with_assignment_each_withdrawal_is_paid_exactly_once() {
    let Some(_) = goldcoind_bin() else {
        eprintln!("GOLDCOIND_BIN unset — skipping");
        return;
    };
    let f = fixture(2, "40.0");
    let cfg = config(&f.vault, &f.redeem);
    let mut a = Operator::assigned(&f.node, &cfg, &f.wifs, 0, 2);
    let mut b = Operator::assigned(&f.node, &cfg, &f.wifs, 1, 2);
    let w5 = withdrawal(5, 30_00000000, &f.dest);
    let w7 = withdrawal(7, 30_00000000, &f.dest);

    // The SAME staggered discovery that produced the double payment.
    a.exec.ingest_discovered(&[w5.clone(), w7.clone()]).unwrap();
    b.exec.ingest_discovered(&[w7.clone()]).unwrap();
    b.exec.tick().await.unwrap();
    b.exec.ingest_discovered(&[w5.clone()]).unwrap();

    let miner = f.node.cli(&["getnewaddress"]);
    for _ in 1..=6 {
        let _ = a.exec.tick().await;
        let _ = b.exec.tick().await;
        f.node.cli(&["generatetoaddress", "2", &miner]);
    }

    let mut seen: Vec<(String, u64)> = Vec::new();
    for op in [&a, &b] {
        for i in [5i64, 7] {
            if let Some(t) = op.db().get_payout(i).unwrap().and_then(|p| p.txid_hex) {
                let amt = paid_to(&f.node, &t, &f.dest);
                if amt > 0 && !seen.iter().any(|(x, _)| *x == t) {
                    seen.push((t, amt));
                }
            }
        }
    }
    let total: u64 = seen.iter().map(|(_, a)| *a).sum();
    println!(
        "\nM4: {} distinct confirmed payments totalling {} GLC",
        seen.len(),
        total as f64 / 1e8
    );
    assert!(
        total <= 60_00000000,
        "with builder-authoritative assignment no withdrawal may be paid twice; \
         got {} GLC across {} payments",
        total as f64 / 1e8,
        seen.len()
    );
}

/// **Records the PRE-FIX behaviour.** Deliberately runs operators with no
/// assignment, which is what Phase 7g measured and ADR-0019 §2.2 documents.
/// Kept so the baseline is reproducible, not because it is desirable.
#[tokio::test]
async fn m2_can_two_operators_pay_the_same_withdrawal_twice() {
    // THE question. Both operators hold every vault key here, which is the
    // TEST-ONLY collector deliberately bypassing the Phase 7e signer check.
    // So this measures what the EXECUTOR alone prevents — the worst case if
    // the signer's own-state check were ever weakened or absent.
    let Some(_) = goldcoind_bin() else {
        eprintln!("GOLDCOIND_BIN unset — skipping");
        return;
    };
    let f = fixture(2, "40.0");
    let cfg = config(&f.vault, &f.redeem);
    let mut a = Operator::new(&f.node, &cfg, &f.wifs);
    let mut b = Operator::new(&f.node, &cfg, &f.wifs);
    let w5 = withdrawal(5, 30_00000000, &f.dest);
    let w7 = withdrawal(7, 30_00000000, &f.dest);

    println!("\n=== M2: double-payment exposure with the signer check BYPASSED ===");
    println!("2 x 40 GLC utxos; withdrawals 5 and 7 of 30 GLC each");
    println!("expected total to dest if each is paid exactly once: 60 GLC\n");

    a.exec.ingest_discovered(&[w5.clone(), w7.clone()]).unwrap();
    b.exec.ingest_discovered(&[w7.clone()]).unwrap();
    b.exec.tick().await.unwrap();
    b.exec.ingest_discovered(&[w5.clone()]).unwrap();

    for round in 1..=6 {
        a.exec.tick().await.unwrap();
        b.exec.tick().await.unwrap();
        // Confirm anything broadcast so balances settle.
        let miner = f.node.cli(&["getnewaddress"]);
        f.node.cli(&["generatetoaddress", "2", &miner]);
        println!(
            "round {round}: A5={:?} A7={:?} | B5={:?} B7={:?} | dest={} GLC",
            a.state(5),
            a.state(7),
            b.state(5),
            b.state(7),
            0.0
        );
    }

    // THE decisive step. A believes 7 is unpaid (AwaitingFunds) because it
    // never saw B pay it. If the vault is refunded, does A pay 7 a SECOND
    // time?
    println!("\n-- refunding the vault; A still believes w7 is unpaid --");
    let miner = f.node.cli(&["getnewaddress"]);
    f.node.cli(&["sendtoaddress", &f.vault, "40.0"]);
    // Goldcoin still enforces the old coin-age priority rule: a freshly
    // created output is rejected as "insufficient priority" until it ages.
    // Mining generously here keeps the measurement about DOUBLE PAYMENT
    // rather than about relay policy.
    f.node.cli(&["generatetoaddress", "30", &miner]);
    for round in 1..=6 {
        if let Err(e) = a.exec.tick().await {
            println!("  A tick error: {e}");
        }
        if let Err(e) = b.exec.tick().await {
            println!("  B tick error: {e}");
        }
        f.node.cli(&["generatetoaddress", "2", &miner]);
        println!(
            "refund round {round}: A5={:?} A7={:?} | B5={:?} B7={:?} | dest={} GLC",
            a.state(5),
            a.state(7),
            b.state(5),
            b.state(7),
            0.0
        );
    }

    // Why did the total not rise? Compare what each operator believes it
    // paid, and what the chain actually contains.
    println!("\n-- what each operator believes it paid --");
    for (name, op) in [("A", &a), ("B", &b)] {
        for i in [5i64, 7] {
            let p = op.db().get_payout(i).unwrap();
            println!(
                "  {name} w{i}: txid={:?} state={:?}",
                p.as_ref().and_then(|p| p.txid_hex.clone()),
                op.state(i)
            );
        }
    }
    println!("-- chain status of every believed txid --");
    for (name, op) in [("A", &a), ("B", &b)] {
        for i in [5i64, 7] {
            if let Some(t) = op.db().get_payout(i).unwrap().and_then(|p| p.txid_hex) {
                match f.node.try_cli(&["getrawtransaction", &t, "1"]) {
                    Some(j) => {
                        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
                        println!(
                            "  {name} w{i} {}: confirmations={:?} blockhash={:?}",
                            &t[..16],
                            v.get("confirmations"),
                            v.get("blockhash")
                                .and_then(|b| b.as_str())
                                .map(|b| &b[..16])
                        );
                    }
                    None => println!("  {name} w{i} {}: NOT KNOWN TO THE NODE", &t[..16]),
                }
            }
        }
    }

    let utxos: serde_json::Value = serde_json::from_str(&f.node.cli(&[
        "listunspent",
        "0",
        "9999999",
        &format!("[\"{}\"]", f.dest),
    ]))
    .unwrap();
    println!("-- payments actually on chain to dest --");
    for e in utxos.as_array().unwrap() {
        println!("  {} GLC  txid={}", e["amount"], e["txid"]);
    }

    // Per-WITHDRAWAL accounting: how many distinct CONFIRMED transactions
    // paid this destination, and on whose behalf.
    println!("\n-- per-withdrawal payment accounting --");
    let mut seen: Vec<(String, u64)> = Vec::new();
    for (name, op) in [("A", &a), ("B", &b)] {
        for i in [5i64, 7] {
            if let Some(t) = op.db().get_payout(i).unwrap().and_then(|p| p.txid_hex) {
                let amt = paid_to(&f.node, &t, &f.dest);
                println!("  {name} w{i}: {} GLC via {}", amt as f64 / 1e8, &t[..16]);
                if amt > 0 && !seen.iter().any(|(x, _)| *x == t) {
                    seen.push((t, amt));
                }
            }
        }
    }
    let total: u64 = seen.iter().map(|(_, a)| *a).sum();
    println!(
        "\nDISTINCT CONFIRMED PAYMENTS = {} totalling {} GLC (expected 2 / 60 GLC)",
        seen.len(),
        total as f64 / 1e8
    );
    println!(
        "{}",
        if total > 60_00000000 {
            "*** OVERPAID — a withdrawal was paid MORE THAN ONCE ***"
        } else {
            "no overpayment"
        }
    );
}
