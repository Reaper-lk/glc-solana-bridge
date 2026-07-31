//! Full round-trip end-to-end test (Phase 6, ADR-0013):
//!
//! ```text
//! real Goldcoin deposit  ->  indexer  ->  claim artifact
//!   ->  mint orchestrator  ->  real SPL mint on a real solana-test-validator
//!   ->  burn_wrapped       ->  real WithdrawalRequest PDA
//!   ->  withdrawal discovery + executor
//!   ->  real Goldcoin payout arriving at a real address
//! ```
//!
//! Both chains are genuine: an actual `goldcoind -regtest` and an actual
//! `solana-test-validator` running the actual compiled program. Nothing in
//! the value path is mocked.
//!
//! Skipped (not failed) unless `GOLDCOIND_BIN`, `GOLDCOIN_CLI_BIN`, the
//! compiled program, and `solana-test-validator` are all available.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient as BlockingRpcClient;
#[allow(deprecated)]
use solana_sdk::bpf_loader_upgradeable;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;

use glc_relayer::glc;
use glc_relayer::glc::config::{
    IndexerConfig, RawIndexerConfig, RpcConfig, RpcConfigValidated, ValueCaps,
};
use glc_relayer::glc::db::{Db, DepositState};
use glc_relayer::glc::indexer::Indexer;
use glc_relayer::glc::rpc::RpcClient as GlcRpcClient;
use glc_relayer::glc::withdrawal_db::WithdrawalState;
use glc_relayer::orchestrator::Orchestrator;
use glc_relayer::solana::instruction as glc_ix;
use glc_relayer::solana::rpc::RealSolanaRpc;
use glc_relayer::withdrawal::adapter::RealPayoutRpc;
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::discovery;
use glc_relayer::withdrawal::executor::WithdrawalExecutor;

const DECLARED_PROGRAM_ID: &str = "77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq";

// =====================================================================
// Environment gating
// =====================================================================

fn goldcoind_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIND_BIN").map(PathBuf::from)
}
fn goldcoin_cli_bin() -> Option<PathBuf> {
    std::env::var_os("GOLDCOIN_CLI_BIN").map(PathBuf::from)
}
fn program_so() -> Option<PathBuf> {
    let p = std::env::var("GLC_BRIDGE_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../target/deploy/glc_bridge.so"));
    p.exists().then_some(p)
}
fn validator_available() -> bool {
    Command::new("solana-test-validator")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// =====================================================================
// Goldcoin regtest node
// =====================================================================

struct GoldNode {
    child: Child,
    cli: PathBuf,
    datadir: tempfile::TempDir,
    rpc_port: u16,
    user: String,
    password: String,
}

impl GoldNode {
    fn start(bin: &Path, cli: &Path) -> Self {
        let datadir = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let user = "e2e_user".to_string();
        let password = format!("e2e_pw_{}", std::process::id());
        let child = Command::new(bin)
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
            .expect("spawn goldcoind");
        let n = GoldNode {
            child,
            cli: cli.to_path_buf(),
            datadir,
            rpc_port,
            user,
            password,
        };
        for _ in 0..120 {
            if n.try_cli(&["getblockcount"]).is_some() {
                return n;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("goldcoind never became ready");
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
    fn try_cli(&self, args: &[&str]) -> Option<String> {
        let o = self.cli_cmd().args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    fn cli(&self, args: &[&str]) -> String {
        let o = self.cli_cmd().args(args).output().expect("goldcoin-cli");
        assert!(
            o.status.success(),
            "goldcoin-cli {:?} failed: {}",
            args,
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    }
    fn mine(&self, n: u32, to: &str) {
        self.cli(&["generatetoaddress", &n.to_string(), to]);
    }
    /// A real deposit: pays the vault and binds a Solana recipient in a
    /// 32-byte OP_RETURN, exactly the Phase 4 shape.
    fn send_deposit(&self, vault: &str, amount_glc: f64, recipient: &[u8; 32]) -> String {
        let payload = glc::hex::encode(recipient);
        let outputs = format!("{{\"{vault}\":{amount_glc},\"data\":\"{payload}\"}}");
        let raw = self.cli(&["createrawtransaction", "[]", &outputs]);
        let funded: serde_json::Value =
            serde_json::from_str(&self.cli(&["fundrawtransaction", &raw])).unwrap();
        let signed: serde_json::Value = serde_json::from_str(
            &self.cli(&["signrawtransaction", funded["hex"].as_str().unwrap()]),
        )
        .unwrap();
        self.cli(&["sendrawtransaction", signed["hex"].as_str().unwrap()])
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
    fn raw_rpc_config(&self) -> RpcConfig {
        RpcConfig {
            url: format!("http://127.0.0.1:{}", self.rpc_port),
            user: self.user.clone(),
            password: self.password.clone(),
            connect_timeout_ms: 5_000,
            read_timeout_ms: 30_000,
        }
    }
    fn script_pubkey_of(&self, addr: &str) -> String {
        let v: serde_json::Value =
            serde_json::from_str(&self.cli(&["validateaddress", addr])).unwrap();
        v["scriptPubKey"].as_str().unwrap().to_string()
    }
    fn received(&self, addr: &str) -> f64 {
        self.cli(&["getreceivedbyaddress", addr, "1"])
            .parse()
            .unwrap()
    }
}

impl Drop for GoldNode {
    fn drop(&mut self) {
        let _ = self.cli_cmd().arg("stop").output();
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// =====================================================================
// Solana test validator
// =====================================================================

struct SolNode {
    child: Child,
    _ledger: tempfile::TempDir,
    url: String,
}

impl SolNode {
    fn start(so: &Path, program_id: &Pubkey, upgrade_authority: &Pubkey) -> Self {
        let ledger = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let faucet_port = free_port();
        let child = Command::new("solana-test-validator")
            .arg("--reset")
            .arg("--quiet")
            .arg("--ledger")
            .arg(ledger.path())
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .arg("--faucet-port")
            .arg(faucet_port.to_string())
            .arg("--bind-address")
            .arg("127.0.0.1")
            .arg("--upgradeable-program")
            .arg(program_id.to_string())
            .arg(so)
            .arg(upgrade_authority.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn solana-test-validator");
        let n = SolNode {
            child,
            _ledger: ledger,
            url: format!("http://127.0.0.1:{rpc_port}"),
        };
        let c = n.client();
        for _ in 0..240 {
            if c.get_health().is_ok() {
                return n;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("solana-test-validator never became healthy");
    }
    fn client(&self) -> BlockingRpcClient {
        BlockingRpcClient::new_with_commitment(self.url.clone(), CommitmentConfig::finalized())
    }
}

impl Drop for SolNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Waits for an SPL token account to report `expected` atomic units.
///
/// The orchestrator submits at `confirmed` commitment while this client
/// reads at `finalized`, so a freshly-landed mint is briefly invisible here.
/// Polling avoids racing finality rather than weakening the assertion.
fn await_token_balance(c: &BlockingRpcClient, ata: &Pubkey, expected: u64, what: &str) {
    for _ in 0..120 {
        if let Ok(b) = c.get_token_account_balance(ata) {
            if b.amount == expected.to_string() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let actual = c
        .get_token_account_balance(ata)
        .map(|b| b.amount)
        .unwrap_or_else(|e| format!("<error: {e}>"));
    panic!("{what}: expected {expected} atomic units, got {actual}");
}

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    let mut o = [0u8; 8];
    o.copy_from_slice(&h[..8]);
    o
}

fn program_data_pda(pid: &Pubkey) -> Pubkey {
    #[allow(deprecated)]
    Pubkey::find_program_address(&[pid.as_ref()], &bpf_loader_upgradeable::id()).0
}

fn airdrop(c: &BlockingRpcClient, to: &Pubkey, lamports: u64) {
    let sig = c.request_airdrop(to, lamports).expect("airdrop");
    for _ in 0..200 {
        if c.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("airdrop never confirmed");
}

// =====================================================================
// The test
// =====================================================================

#[tokio::test(flavor = "multi_thread")]
async fn deposit_to_mint_to_burn_to_goldcoin_payout() {
    let (Some(gbin), Some(gcli)) = (goldcoind_bin(), goldcoin_cli_bin()) else {
        eprintln!("skipping e2e: GOLDCOIND_BIN / GOLDCOIN_CLI_BIN not set");
        return;
    };
    let Some(so) = program_so() else {
        eprintln!("skipping e2e: compiled program not found (run `anchor build`)");
        return;
    };
    if !validator_available() {
        eprintln!("skipping e2e: solana-test-validator not on PATH");
        return;
    }

    // ---------- chains up ----------
    let gold = GoldNode::start(&gbin, &gcli);
    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let authority = Keypair::new();
    let sol = SolNode::start(&so, &program_id, &authority.pubkey());
    let sc = sol.client();
    airdrop(&sc, &authority.pubkey(), 20_000_000_000);
    let submitter = Keypair::new();
    airdrop(&sc, &submitter.pubkey(), 20_000_000_000);

    // ---------- Goldcoin: vault + funds ----------
    let miner = gold.cli(&["getnewaddress"]);
    let vault = gold.cli(&["getnewaddress"]);
    let payout_dest = gold.cli(&["getnewaddress"]);
    gold.mine(130, &miner);
    let vault_script = gold.script_pubkey_of(&vault);

    // ---------- Solana: initialize + wrapped mint ----------
    let validators: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let validator_pubkeys: Vec<Pubkey> = validators.iter().map(|k| k.pubkey()).collect();
    let threshold: u8 = 2;
    let (bridge_config, _) = glc_ix::bridge_config_pda(&program_id);
    let (validator_set, _) = glc_ix::validator_set_pda(&program_id);
    let (mint_authority, _) = glc_ix::mint_authority_pda(&program_id);

    let mut init_data = anchor_disc("initialize").to_vec();
    init_data.extend_from_slice(&(validator_pubkeys.len() as u32).to_le_bytes());
    for v in &validator_pubkeys {
        init_data.extend_from_slice(v.as_ref());
    }
    init_data.push(threshold);
    init_data.extend_from_slice(&0u64.to_le_bytes()); // min_deposit
    init_data.extend_from_slice(&0u64.to_le_bytes()); // min_withdrawal
                                                      // Phase 7a (ADR-0014): governance timelock. No default exists —
                                                      // the program rejects zero — so tests state it explicitly.
    init_data.extend_from_slice(&3_600i64.to_le_bytes()); // governance_timelock_seconds
    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(validator_set, false),
            AccountMeta::new_readonly(program_id, false),
            AccountMeta::new_readonly(program_data_pda(&program_id), false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: init_data,
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    ))
    .expect("initialize");

    let wrapped_mint_kp = Keypair::new();
    let create_mint_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new_readonly(mint_authority, false),
            AccountMeta::new(wrapped_mint_kp.pubkey(), true),
            AccountMeta::new_readonly(spl_token::ID, false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: anchor_disc("create_wrapped_mint").to_vec(),
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[create_mint_ix],
        Some(&authority.pubkey()),
        &[&authority, &wrapped_mint_kp],
        bh,
    ))
    .expect("create_wrapped_mint");
    let wrapped_mint = wrapped_mint_kp.pubkey();

    // The depositor's Solana wallet, and its ATA (must pre-exist).
    let user = Keypair::new();
    airdrop(&sc, &user.pubkey(), 20_000_000_000);
    let user_ata =
        spl_associated_token_account::get_associated_token_address(&user.pubkey(), &wrapped_mint);
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[
            spl_associated_token_account::instruction::create_associated_token_account(
                &authority.pubkey(),
                &user.pubkey(),
                &wrapped_mint,
                &spl_token::ID,
            ),
        ],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    ))
    .expect("create user ATA");

    // ---------- STEP 1: real Goldcoin deposit ----------
    let deposit_glc = 40.0_f64;
    let deposit_atomic = 40_00000000u64;
    let deposit_txid = gold.send_deposit(&vault, deposit_glc, &user.pubkey().to_bytes());
    gold.mine(3, &miner);

    // ---------- STEP 2: indexer -> ReadyForSignature ----------
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite3");
    Db::open(&db_path).unwrap();

    let indexer_config = IndexerConfig::validate(RawIndexerConfig {
        rpc: gold.raw_rpc_config(),
        db_path: db_path.clone(),
        vault_script_pubkey_hex: vault_script.clone(),
        confirmation_depth: 2,
        max_reorg_depth: 10,
        min_deposit_atomic: 0,
        value_caps: ValueCaps {
            max_deposit_atomic: None,
            rolling_window: None,
        },
        protocol_version: 1,
        program_id_hex: glc::hex::encode(&program_id.to_bytes()),
        validator_epoch: 0,
        wrapped_mint_hex: glc::hex::encode(&wrapped_mint.to_bytes()),
        node_unavailable_retry_interval_ms: 500,
        poll_interval_ms: 200,
    })
    .expect("indexer config");

    let mut indexer = Indexer::new(
        GlcRpcClient::new(&gold.rpc_config()).unwrap(),
        Db::open(&db_path).unwrap(),
        indexer_config,
    );
    for _ in 0..20 {
        indexer.tick().await.expect("indexer tick");
        let ready = Db::open(&db_path)
            .unwrap()
            .candidates_by_state(DepositState::ReadyForSignature)
            .unwrap();
        if !ready.is_empty() {
            break;
        }
        gold.mine(1, &miner);
    }
    let ready = Db::open(&db_path)
        .unwrap()
        .candidates_by_state(DepositState::ReadyForSignature)
        .unwrap();
    assert_eq!(ready.len(), 1, "the real deposit reached ReadyForSignature");
    assert_eq!(ready[0].txid_hex, deposit_txid);
    assert_eq!(ready[0].amount_atomic, deposit_atomic);

    // ---------- STEP 3: mint orchestrator -> real SPL mint ----------
    let mut orch = Orchestrator::new(
        Db::open(&db_path).unwrap(),
        RealSolanaRpc::new(sol.url.clone(), CommitmentLevel::Confirmed),
        program_id,
        Keypair::try_from(submitter.to_bytes().as_slice()).unwrap(),
        validators
            .iter()
            .map(|k| Keypair::try_from(k.to_bytes().as_slice()).unwrap())
            .collect(),
    );
    let mut minted = false;
    for _ in 0..40 {
        if orch.tick().await.expect("orchestrator tick").minted > 0 {
            minted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(minted, "deposit was minted on the real validator");

    await_token_balance(
        &sc,
        &user_ata,
        deposit_atomic,
        "user holds exactly the deposited amount in wrapped GLC",
    );

    // ---------- STEP 4: burn_wrapped -> real WithdrawalRequest PDA ----------
    let burn_atomic = 15_00000000u64; // 15 GLC back to Goldcoin
    let (withdrawal_pda, _) = discovery::withdrawal_pda(&program_id, 0);
    let mut burn_data = anchor_disc("burn_wrapped").to_vec();
    burn_data.extend_from_slice(&burn_atomic.to_le_bytes());
    burn_data.extend_from_slice(&(payout_dest.len() as u32).to_le_bytes());
    burn_data.extend_from_slice(payout_dest.as_bytes());
    let burn_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(wrapped_mint, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new(withdrawal_pda, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: burn_data,
    };
    let bh = sc.get_latest_blockhash().unwrap();
    sc.send_and_confirm_transaction(&Transaction::new_signed_with_payer(
        &[burn_ix],
        Some(&user.pubkey()),
        &[&user],
        bh,
    ))
    .expect("burn_wrapped");

    await_token_balance(
        &sc,
        &user_ata,
        deposit_atomic - burn_atomic,
        "wrapped tokens were really burned",
    );

    // ---------- STEP 5: withdrawal discovery over the real validator ----------
    let discovery_rpc = RealSolanaRpc::new(sol.url.clone(), CommitmentLevel::Finalized);
    let mut found = Vec::new();
    for _ in 0..40 {
        found = discovery::scan_withdrawals(
            &discovery_rpc,
            &program_id,
            CommitmentLevel::Finalized,
            1_000,
            0,
        )
        .await
        .expect("scan");
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(found.len(), 1, "the real WithdrawalRequest was discovered");
    assert_eq!(found[0].withdrawal_index, 0);
    assert_eq!(found[0].amount_atomic, burn_atomic);
    assert_eq!(found[0].glc_address, payout_dest);

    // ---------- STEP 6: executor -> real Goldcoin payout ----------
    let w_config = WithdrawalConfig::validate(RawWithdrawalConfig {
        vault_address: vault.clone(),
        change_address: vault.clone(),
        fee_rate_per_kb: 100_000,
        dust_threshold_atomic: 5_400,
        vault_min_confirmations: 1,
        confirmation_depth: 2,
        max_inputs_per_payout: 20,
        reservation_timeout_secs: 900,
        discovery_commitment: "finalized".into(),
        poll_interval_ms: 500,
    })
    .expect("withdrawal config");

    let make_executor = || {
        WithdrawalExecutor::new(
            Db::open(&db_path).unwrap(),
            RealPayoutRpc::new(GlcRpcClient::new(&gold.rpc_config()).unwrap()),
            w_config.clone(),
        )
    };

    let mut exec = make_executor();
    exec.ingest_discovered(&found).expect("ingest");
    exec.tick().await.expect("withdrawal tick");

    let state = Db::open(&db_path)
        .unwrap()
        .get_withdrawal(0)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(
        state,
        WithdrawalState::Confirming,
        "payout was signed and broadcast to the real Goldcoin node"
    );

    gold.mine(3, &miner);
    for _ in 0..10 {
        make_executor().tick().await.expect("withdrawal tick");
        let s = Db::open(&db_path)
            .unwrap()
            .get_withdrawal(0)
            .unwrap()
            .unwrap()
            .state;
        if s == WithdrawalState::Completed {
            break;
        }
        gold.mine(1, &miner);
    }

    // ---------- the round trip is closed ----------
    let final_state = Db::open(&db_path)
        .unwrap()
        .get_withdrawal(0)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(final_state, WithdrawalState::Completed);

    let received = gold.received(&payout_dest);
    assert!(
        (received - 15.0).abs() < 1e-9,
        "the destination received exactly 15.0 GLC (the burned amount, vault paid the fee); got {received}"
    );

    let payout = Db::open(&db_path).unwrap().get_payout(0).unwrap().unwrap();
    assert_eq!(
        payout.payout_atomic, burn_atomic,
        "payout == burned amount (D3)"
    );
    assert!(payout.fee_atomic > 0, "the vault absorbed a real fee");
    assert!(payout.completed_at.is_some());

    // And exactly one payout exists for that withdrawal — never two.
    let payouts: i64 = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM withdrawal_payouts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(payouts, 1);
}
