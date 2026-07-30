//! Real `solana-test-validator` end-to-end test (ADR-0012, Phase 5).
//!
//! Deploys the actual compiled on-chain program (`target/deploy/glc_bridge.so`),
//! initializes the bridge and creates the wrapped mint for real, seeds a
//! Phase-4-shaped SQLite database with one `ReadyForSignature` deposit, runs
//! the real [`Orchestrator`] (with [`RealSolanaRpc`], not a mock) against the
//! real validator, and asserts a genuine SPL mint lands in the recipient's
//! associated token account.
//!
//! Skipped (not failed) unless both the compiled program and the
//! `solana-test-validator` binary are available — mirrors
//! `tests/regtest_indexer.rs`'s env-gating pattern exactly, so `cargo test`
//! still passes in environments without a built on-chain program. Every
//! artifact (ledger, keypairs) lives under a fresh `tempfile` tempdir, torn
//! down at the end; nothing is ever committed.

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

use glc_relayer::glc::db::{Db, DepositState, NewBlock, NewCandidate, NewClaimArtifact};
use glc_relayer::glc::deposit::build_claim_message;
use glc_relayer::orchestrator::Orchestrator;
use glc_relayer::solana::instruction as glc_ix;
use glc_relayer::solana::rpc::RealSolanaRpc;

/// The placeholder program id `declare_id!`'d in `programs/glc-bridge/src/lib.rs`
/// (Anchor.toml: "no known private key" — replaced via `anchor keys sync`
/// once a real deploy keypair exists). `--upgradeable-program` bakes the
/// program directly into genesis state rather than sending a live deploy
/// transaction, so no signature from this address is ever required — we can
/// deploy at exactly this id even without its private key, and the
/// on-chain program's own `crate::ID` (used inside `mint_wrapped`'s message
/// reconstruction and `initialize`'s `Program<'info, ..>` constraint) then
/// matches reality.
const DECLARED_PROGRAM_ID: &str = "77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq";

fn program_so_path() -> Option<PathBuf> {
    let p = std::env::var("GLC_BRIDGE_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("../target/deploy/glc_bridge.so"));
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn solana_test_validator_available() -> bool {
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

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

// ---------------------------------------------------------------------
// Validator process
// ---------------------------------------------------------------------

struct LocalValidator {
    child: Child,
    _ledger: tempfile::TempDir,
    rpc_url: String,
}

impl LocalValidator {
    fn start(so_path: &Path, program_id: &Pubkey, upgrade_authority: &Pubkey) -> Self {
        let ledger = tempfile::tempdir().expect("tempdir");
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
            .arg(so_path)
            .arg(upgrade_authority.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn solana-test-validator — check it is on PATH");

        let validator = LocalValidator {
            child,
            _ledger: ledger,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
        };
        validator.wait_ready();
        validator
    }

    fn wait_ready(&self) {
        let client = BlockingRpcClient::new_with_commitment(
            self.rpc_url.clone(),
            CommitmentConfig::confirmed(),
        );
        for _ in 0..200 {
            if client.get_health().is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("solana-test-validator did not become healthy within 20s");
    }
}

impl Drop for LocalValidator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn airdrop(client: &BlockingRpcClient, to: &Pubkey, lamports: u64) {
    let sig = client
        .request_airdrop(to, lamports)
        .expect("airdrop request");
    for _ in 0..100 {
        if client.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("airdrop did not confirm within 10s");
}

// ---------------------------------------------------------------------
// One-time setup instructions (governance/admin calls — never part of the
// relayer's own production surface, which only ever builds `mint_wrapped`;
// hand-rolled here the same way, for the same reason: no dependency on the
// on-chain crate, owner decision R1).
// ---------------------------------------------------------------------

fn program_data_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id()).0
}

#[allow(clippy::too_many_arguments)]
fn build_initialize_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    bridge_config: &Pubkey,
    validator_set: &Pubkey,
    validators: &[Pubkey],
    threshold: u8,
) -> Instruction {
    let mut data = anchor_discriminator("initialize").to_vec();
    data.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        data.extend_from_slice(v.as_ref());
    }
    data.push(threshold);
    data.extend_from_slice(&0u64.to_le_bytes()); // min_deposit
    data.extend_from_slice(&0u64.to_le_bytes()); // min_withdrawal

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*bridge_config, false),
            AccountMeta::new(*validator_set, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(program_data_pda(program_id), false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn build_create_wrapped_mint_ix(
    program_id: &Pubkey,
    admin: &Pubkey,
    bridge_config: &Pubkey,
    mint_authority: &Pubkey,
    wrapped_mint: &Pubkey,
) -> Instruction {
    let data = anchor_discriminator("create_wrapped_mint").to_vec();
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(*bridge_config, false),
            AccountMeta::new_readonly(*mint_authority, false),
            AccountMeta::new(*wrapped_mint, true),
            AccountMeta::new_readonly(spl_token::ID, false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

// ---------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------

// The blocking `solana_client::rpc_client::RpcClient` used for setup calls
// below requires a multi-threaded Tokio runtime (it panics under the
// default current-thread `#[tokio::test]` runtime).
#[tokio::test(flavor = "multi_thread")]
async fn deposit_is_signed_aggregated_submitted_and_really_minted_on_a_local_validator() {
    let Some(so_path) = program_so_path() else {
        eprintln!(
            "skipping: compiled program not found (expected ../target/deploy/glc_bridge.so — \
             run `anchor build` first, or set GLC_BRIDGE_SO)"
        );
        return;
    };
    if !solana_test_validator_available() {
        eprintln!("skipping: solana-test-validator not found on PATH");
        return;
    }

    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let upgrade_authority = Keypair::new();
    let validator = LocalValidator::start(&so_path, &program_id, &upgrade_authority.pubkey());
    let client = BlockingRpcClient::new_with_commitment(
        validator.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );

    // Fund every keypair that pays rent or fees in what follows.
    airdrop(&client, &upgrade_authority.pubkey(), 10_000_000_000);
    let submitter = Keypair::new();
    airdrop(&client, &submitter.pubkey(), 10_000_000_000);
    let recipient = Keypair::new();

    // Federation: 3 validators, threshold 2 — the orchestrator (Phase 5
    // bootstrap topology, owner decision R2) holds all 3 keys itself.
    let validator_keys: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let validator_pubkeys: Vec<Pubkey> = validator_keys.iter().map(|k| k.pubkey()).collect();
    let threshold: u8 = 2;

    let (bridge_config, _) = glc_ix::bridge_config_pda(&program_id);
    let (validator_set, _) = glc_ix::validator_set_pda(&program_id);
    let (mint_authority, _) = glc_ix::mint_authority_pda(&program_id);

    // `initialize`.
    let init_ix = build_initialize_ix(
        &program_id,
        &upgrade_authority.pubkey(),
        &bridge_config,
        &validator_set,
        &validator_pubkeys,
        threshold,
    );
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&upgrade_authority.pubkey()),
        &[&upgrade_authority],
        bh,
    );
    client
        .send_and_confirm_transaction(&tx)
        .expect("initialize must land");

    // `create_wrapped_mint` — the mint is a fresh keypair-based account
    // (not a PDA), so it must co-sign its own creation.
    let wrapped_mint_kp = Keypair::new();
    let create_mint_ix = build_create_wrapped_mint_ix(
        &program_id,
        &upgrade_authority.pubkey(),
        &bridge_config,
        &mint_authority,
        &wrapped_mint_kp.pubkey(),
    );
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_mint_ix],
        Some(&upgrade_authority.pubkey()),
        &[&upgrade_authority, &wrapped_mint_kp],
        bh,
    );
    client
        .send_and_confirm_transaction(&tx)
        .expect("create_wrapped_mint must land");
    let wrapped_mint = wrapped_mint_kp.pubkey();

    // The recipient's ATA must already exist before `mint_wrapped` runs —
    // Phase 5 never creates it (see the final report's noted limitation).
    let recipient_ata = spl_associated_token_account::get_associated_token_address(
        &recipient.pubkey(),
        &wrapped_mint,
    );
    let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &upgrade_authority.pubkey(),
        &recipient.pubkey(),
        &wrapped_mint,
        &spl_token::ID,
    );
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix],
        Some(&upgrade_authority.pubkey()),
        &[&upgrade_authority],
        bh,
    );
    client
        .send_and_confirm_transaction(&tx)
        .expect("recipient ATA creation must land");

    // Seed a genuinely self-consistent ReadyForSignature deposit, built
    // against the REAL deployed program id / wrapped mint / recipient.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relayer.sqlite3");
    let txid = [0x77; 32];
    let vout: u32 = 0;
    let amount_atomic: u64 = 1_234_500_000_000; // 12345.0 GLC at 8 decimals
    let validator_epoch: u64 = 0; // set by `initialize`
    let protocol_version: u8 = 1;

    let deposit_id = {
        let mut db = Db::open(&db_path).unwrap();
        let block = NewBlock {
            height: 1,
            hash: [0x11; 32],
            prev_hash: [0u8; 32],
            block_time: 0,
            indexed_at: 0,
        };
        let candidate = NewCandidate {
            txid,
            vout: vout as i64,
            amount_atomic,
            recipient: recipient.pubkey().to_bytes(),
            block_height: 1,
            block_hash: [0x11; 32],
            raw_tx_hex: "deadbeef".to_string(),
            discovered_at: 0,
            initial_state: DepositState::Candidate,
            failure_reason: None,
        };
        let ids = db.ingest_block(&block, &[candidate]).unwrap();
        let deposit_id = ids[0];

        let message = build_claim_message(
            protocol_version,
            &program_id.to_bytes(),
            validator_epoch,
            &txid,
            vout,
            amount_atomic,
            &recipient.pubkey().to_bytes(),
            &wrapped_mint.to_bytes(),
        );
        let message_hash: [u8; 32] = Sha256::digest(message).into();
        let artifact = NewClaimArtifact {
            deposit_id,
            canonical_message: message,
            message_hash,
            protocol_version,
            validator_epoch,
            program_id: program_id.to_bytes(),
            wrapped_mint: wrapped_mint.to_bytes(),
            created_at: 0,
        };
        db.transition_state(deposit_id, DepositState::Confirming, 1, None, None)
            .unwrap();
        db.transition_state(
            deposit_id,
            DepositState::ReadyForSignature,
            2,
            None,
            Some(&artifact),
        )
        .unwrap();
        deposit_id
    };

    // Run the REAL orchestrator against the REAL validator.
    let rpc = RealSolanaRpc::new(validator.rpc_url.clone(), CommitmentLevel::Confirmed);
    let db = Db::open(&db_path).unwrap();
    let mut orch = Orchestrator::new(db, rpc, program_id, submitter, validator_keys);

    let mut minted = false;
    for _ in 0..40 {
        let report = orch.tick().await.expect("tick must not error");
        if report.minted > 0 {
            minted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(minted, "deposit did not reach Minted within the deadline");

    let final_state = Db::open(&db_path)
        .unwrap()
        .get_by_id(deposit_id)
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(final_state, DepositState::Minted);

    // The substantive assertion: a REAL SPL mint landed in the recipient's
    // real associated token account.
    let balance = client
        .get_token_account_balance(&recipient_ata)
        .expect("recipient ATA must hold a balance after minting");
    assert_eq!(balance.amount, amount_atomic.to_string());

    // And the claim PDA — the replay guard — genuinely exists on-chain,
    // owned by our program.
    let (claim_pda, _) = glc_ix::deposit_claim_pda(&program_id, &txid, vout);
    let claim_account = client
        .get_account(&claim_pda)
        .expect("claim PDA must exist on-chain");
    assert_eq!(claim_account.owner, program_id);
}
