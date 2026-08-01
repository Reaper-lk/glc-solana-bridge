//! Real-node integration tests for the Phase 6 withdrawal executor
//! (ADR-0013).
//!
//! Requires an actual `goldcoind` — never mocked — via `GOLDCOIND_BIN` /
//! `GOLDCOIN_CLI_BIN`. Skipped (not failed) when unset, mirroring
//! `regtest_indexer.rs` exactly, so `cargo test` still passes without a
//! fetched binary.
//!
//! Everything lives in a throwaway `tempfile` datadir with per-process
//! credentials, torn down at the end; nothing is ever committed.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use glc_relayer::glc::config::RpcConfigValidated;
use glc_relayer::glc::db::Db;
use glc_relayer::glc::rpc::RpcClient;
use glc_relayer::glc::withdrawal_db::{NewWithdrawalRequest, WithdrawalState};
use glc_relayer::solana::epoch::EpochObservation;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::address::decode_p2pkh_hash160;
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
        let p2p_port = free_port();
        let user = "glc_w_user".to_string();
        let password = format!("glc_w_pw_{}", std::process::id());
        let child = Command::new(goldcoind)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.path().display()))
            .arg("-daemon=0")
            .arg("-printtoconsole=0")
            .arg(format!("-rpcuser={user}"))
            .arg(format!("-rpcpassword={password}"))
            .arg(format!("-rpcport={rpc_port}"))
            .arg(format!("-port={p2p_port}"))
            .arg("-rpcbind=127.0.0.1")
            .arg("-rpcallowip=127.0.0.1")
            .arg("-fallbackfee=0.0001")
            .arg("-txindex=1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn goldcoind — check GOLDCOIND_BIN");
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

    /// Like `cli` but tolerates failure — used for imports, which raise a
    /// method error when the address is already known.
    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let o = self.cli_cmd().args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
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
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("goldcoind did not become ready");
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
        let _ = self.cli_cmd().arg("stop").output();
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reduces a `listunspent` JSON array to the `[{"txid":..,"vout":..}]` shape
/// `lockunspent` expects.
fn compact_outpoints(listunspent_json: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(listunspent_json).unwrap();
    let items: Vec<serde_json::Value> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::json!({ "txid": e["txid"], "vout": e["vout"] }))
        .collect();
    serde_json::Value::Array(items).to_string()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn config(vault: &str, redeem: &str, change: &str, depth: i64) -> WithdrawalConfig {
    WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_redeem_script_hex: redeem.to_string(),
        vault_address: vault.to_string(),
        change_address: change.to_string(),
        fee_rate_per_kb: 100_000, // 0.001 GLC/kB — comfortably above min relay
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: depth,
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
        observed_at: 0,
        observed_at_slot: 1,
    }
}

struct Fixture {
    node: RegtestNode,
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    vault: String,
    redeem: String,
    /// `(vault signer index, WIF)` for every vault key, as a real node's
    /// `dumpprivkey` returns them.
    wifs: Vec<(u8, String)>,
    dest: String,
}

impl Fixture {
    /// Funds a dedicated vault address with `count` distinct mature outputs.
    ///
    /// The vault address belongs to the node's own wallet (owner decision
    /// D2, regtest bootstrap custody), and the wallet does NOT treat it as
    /// special: left alone, `sendtoaddress` happily consumes the vault's own
    /// output as an input for the next send, consolidating everything back
    /// into one UTXO. Each output is therefore locked immediately after it
    /// is created, then all are unlocked before the executor runs. This is a
    /// real property of wallet-held custody, not a test artifact — see
    /// ADR-0013's security notes.
    fn setup(node: RegtestNode, count: usize) -> Self {
        // A real P2SH 2-of-3 vault (ADR-0015), not the Phase 6 single-key
        // stand-in. The node wallet holds all three keys here so the
        // regtest signer can complete a quorum in one call; production
        // splits them across operators (7b follow-on).
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
        // Phase 7e: the executor holds no vault key at all. It collects
        // partial signatures from the designated quorum and assembles the
        // scriptSig itself, so the test needs the KEYS, not a wallet that
        // can sign the whole quorum in one call.
        let wifs: Vec<(u8, String)> = signers
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u8, node.cli(&["dumpprivkey", a])))
            .collect();
        // Without these the vault is invisible to listunspent, and with only
        // the address imported its outputs stay unsolvable (verified).
        let _ = node.try_cli(&["importaddress", &vault, "vault", "false"]);
        let _ = node.try_cli(&["importaddress", &redeem, "vault-redeem", "false", "true"]);

        let dest = node.cli(&["getnewaddress"]);
        let miner = node.cli(&["getnewaddress"]);
        node.cli(&["generatetoaddress", "130", &miner]);
        for _ in 0..count {
            node.cli(&["sendtoaddress", &vault, "50.0"]);
            node.cli(&["generatetoaddress", "1", &miner]);
            let listed = node.cli(&["listunspent", "1", "9999999", &format!("[\"{vault}\"]")]);
            let sel = compact_outpoints(&listed);
            if sel != "[]" {
                node.cli(&["lockunspent", "false", &sel]);
            }
        }
        // Hand the whole set to the executor.
        node.cli(&["lockunspent", "true"]);
        node.cli(&["generatetoaddress", "3", &miner]);
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayer.sqlite3");
        Db::open(&db_path).unwrap();
        Fixture {
            node,
            _dir: dir,
            db_path,
            vault,
            redeem,
            dest,
            wifs,
        }
    }

    fn executor(&self, depth: i64) -> WithdrawalExecutor<RealPayoutRpc, InProcessPayoutCollector> {
        self.executor_with_keys(depth, &self.wifs)
    }

    /// An executor whose quorum holds exactly `wifs`, so a test can model a
    /// partial quorum against a real node.
    fn executor_with_keys(
        &self,
        depth: i64,
        wifs: &[(u8, String)],
    ) -> WithdrawalExecutor<RealPayoutRpc, InProcessPayoutCollector> {
        let client = RpcClient::new(&self.node.rpc_config()).unwrap();
        let cfg = config(&self.vault, &self.redeem, &self.vault, depth);
        let collector = InProcessPayoutCollector::from_wifs(cfg.vault.clone(), wifs)
            .expect("vault keys must match the vault the node built");
        WithdrawalExecutor::new(
            Db::open(&self.db_path).unwrap(),
            RealPayoutRpc::new(client),
            cfg,
            collector,
            std::sync::Arc::new(EpochObservation::seeded(1, now_unix())),
        )
    }

    fn state(&self, i: i64) -> WithdrawalState {
        Db::open(&self.db_path)
            .unwrap()
            .get_withdrawal(i)
            .unwrap()
            .unwrap()
            .state
    }
    fn txid(&self, i: i64) -> Option<String> {
        Db::open(&self.db_path)
            .unwrap()
            .get_payout(i)
            .unwrap()
            .and_then(|p| p.txid_hex)
    }
    fn mine(&self, n: u32) {
        let a = self.node.cli(&["getnewaddress"]);
        self.node.cli(&["generatetoaddress", &n.to_string(), &a]);
    }
    /// Total received by an address, per the node's own accounting.
    fn received(&self, addr: &str) -> f64 {
        self.node
            .cli(&["getreceivedbyaddress", addr, "1"])
            .parse()
            .unwrap()
    }
}

fn maybe_node() -> Option<RegtestNode> {
    let (Some(d), Some(c)) = (goldcoind_bin(), goldcoin_cli_bin()) else {
        eprintln!("skipping: GOLDCOIND_BIN / GOLDCOIN_CLI_BIN not set");
        return None;
    };
    Some(RegtestNode::start(&d, &c))
}

// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn real_payout_reaches_the_destination_and_completes() {
    let Some(node) = maybe_node() else { return };
    let f = Fixture::setup(node, 1);

    let amount: u64 = 10_00000000; // 10 GLC
    let mut e = f.executor(3);
    e.ingest_discovered(&[withdrawal(1, amount, &f.dest)])
        .unwrap();
    e.tick().await.unwrap();

    assert_eq!(
        f.state(1),
        WithdrawalState::Confirming,
        "payout signed and broadcast to a real node from a real P2SH multisig vault"
    );
    let txid = f.txid(1).expect("txid durable before broadcast");

    // The transaction is genuinely in the node's mempool.
    let mempool_entry = f.node.cli(&["getrawtransaction", &txid, "true"]);
    assert!(mempool_entry.contains(&txid));

    f.mine(3);
    f.executor(3).tick().await.unwrap();
    assert_eq!(f.state(1), WithdrawalState::Completed);

    // The substantive assertion: real value arrived at the real address,
    // and it is EXACTLY the burned amount (D3 — the vault paid the fee).
    let received = f.received(&f.dest);
    assert!(
        (received - 10.0).abs() < 1e-9,
        "destination received {received}, expected exactly 10.0"
    );

    let p = Db::open(&f.db_path)
        .unwrap()
        .get_payout(1)
        .unwrap()
        .unwrap();
    assert_eq!(p.payout_atomic, amount);
    assert!(p.fee_atomic > 0, "the vault absorbed a real fee");
}

#[tokio::test(flavor = "multi_thread")]
async fn rebroadcasting_an_identical_payout_is_idempotent_on_a_real_node() {
    let Some(node) = maybe_node() else { return };
    let f = Fixture::setup(node, 1);

    let mut e = f.executor(3);
    e.ingest_discovered(&[withdrawal(1, 5_00000000, &f.dest)])
        .unwrap();
    e.tick().await.unwrap();
    let txid = f.txid(1).unwrap();

    // Several restarts while still unconfirmed: each re-sends the identical
    // bytes. The node accepts a mempool duplicate; nothing is paid twice.
    for _ in 0..3 {
        f.executor(3).tick().await.unwrap();
    }
    assert_eq!(f.txid(1).unwrap(), txid, "txid never changes");

    f.mine(1);
    // Now mined: a further re-send would hit RPC -27, which the client
    // normalises to success rather than an error.
    f.executor(3).tick().await.unwrap();
    assert_ne!(f.state(1), WithdrawalState::IntegrityHalted);

    f.mine(3);
    f.executor(3).tick().await.unwrap();
    assert_eq!(f.state(1), WithdrawalState::Completed);
    let received = f.received(&f.dest);
    assert!(
        (received - 5.0).abs() < 1e-9,
        "exactly one payment of 5 GLC arrived, got {received}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorged_out_payout_recovers_and_pays_exactly_once() {
    let Some(node) = maybe_node() else { return };
    let f = Fixture::setup(node, 1);

    let mut e = f.executor(2);
    e.ingest_discovered(&[withdrawal(1, 7_00000000, &f.dest)])
        .unwrap();
    e.tick().await.unwrap();
    let txid = f.txid(1).unwrap();

    f.mine(1);
    f.executor(2).tick().await.unwrap();
    let block = f
        .node
        .cli(&["getblockhash", &f.node.cli(&["getblockcount"])]);

    // Orphan the block containing the payout.
    f.node.cli(&["invalidateblock", &block]);
    f.executor(2).tick().await.unwrap();

    // Recover: mine again so the transaction is re-included.
    f.mine(3);
    f.executor(2).tick().await.unwrap();
    f.executor(2).tick().await.unwrap();

    assert_eq!(f.txid(1).unwrap(), txid, "same transaction, never rebuilt");
    let received = f.received(&f.dest);
    assert!(
        (received - 7.0).abs() < 1e-9,
        "exactly one payment survived the reorg, got {received}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn insufficient_vault_funds_never_partially_pay_on_a_real_node() {
    let Some(node) = maybe_node() else { return };
    let f = Fixture::setup(node, 1); // vault holds ~50 GLC

    let mut e = f.executor(3);
    e.ingest_discovered(&[withdrawal(1, 500_00000000, &f.dest)])
        .unwrap(); // 500 GLC
    e.tick().await.unwrap();

    assert_eq!(f.state(1), WithdrawalState::AwaitingFunds);
    assert!(f.txid(1).is_none(), "nothing was signed or broadcast");
    assert!(
        f.received(&f.dest) < 1e-9,
        "no partial payment may ever reach the destination"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_vault_utxos_are_combined_deterministically() {
    let Some(node) = maybe_node() else { return };
    let f = Fixture::setup(node, 4); // 4 x 50 GLC

    let mut e = f.executor(2);
    e.ingest_discovered(&[withdrawal(1, 120_00000000, &f.dest)])
        .unwrap(); // needs >2 inputs
    e.tick().await.unwrap();
    assert_eq!(f.state(1), WithdrawalState::Confirming);

    let inputs: i64 = rusqlite::Connection::open(&f.db_path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM withdrawal_payout_inputs WHERE withdrawal_index = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(inputs >= 3, "expected multi-input selection, got {inputs}");

    f.mine(2);
    f.executor(2).tick().await.unwrap();
    assert_eq!(f.state(1), WithdrawalState::Completed);
    let received = f.received(&f.dest);
    assert!(
        (received - 120.0).abs() < 1e-9,
        "destination received {received}, expected exactly 120.0"
    );
}
