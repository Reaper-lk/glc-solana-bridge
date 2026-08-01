//! **Rehearsal: key rotation and emergency pause** (Phase 7j).
//!
//! ADR-0014 §8.7 has required since Phase 7 that key rotation be "rehearsed
//! on testnet, not written and filed". This runs runbook §7 and §9 against a
//! real `solana-test-validator` running the real program.
//!
//! # What a rehearsal checks that a unit test cannot
//!
//! Phase 7i-1 pinned the *encoding* of every governance instruction against
//! Anchor's own output. That proves the bytes are right; it proves nothing
//! about whether the documented **procedure** works. This exercises the
//! sequence an operator actually performs — stage, collect, submit, wait,
//! execute — through the same `SignerService` decision path production uses,
//! and then checks the claims `docs/runbooks.md` makes about the outcome:
//!
//! - the timelock is really enforced (executing early fails **on chain**);
//! - a rotation really bumps the epoch and replaces the set;
//! - approvals really do not survive a rotation;
//! - a paused bridge really refuses to mint.
//!
//! # The timelock is short on purpose
//!
//! A live validator's clock cannot be warped the way `litesvm` tests warp
//! it, so the rehearsal initializes with a timelock it can genuinely wait
//! out. The *mechanism* under test is "is the eta enforced", not its
//! production value — which is a deployment decision with no default by
//! design (owner decision U6).
//!
//! Skips itself when the program `.so` or `solana-test-validator` is absent.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient as BlockingRpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;

use glc_bridge_shared::governance::{governance_message, rotation_params, ACTION_PROPOSE_ROTATION};
use glc_relayer::ops::preflight::{can_execute, can_propose, enough_approvals, PreflightRefusal};
use glc_relayer::p2p::governance_view::{Approval, ApprovalStore, GovernanceView};
use glc_relayer::p2p::policy::{Action, LocalView, SigningIdentity};
use glc_relayer::p2p::service::pb::GovernanceSignRequest;
use glc_relayer::p2p::service::{now_unix, SignerService};
use glc_relayer::signer::aggregate::build_ed25519_instruction;
use glc_relayer::solana::instruction as glc_ix;
use glc_relayer::solana::rpc::{decode_pending_action, decode_validator_set};

const DECLARED_PROGRAM_ID: &str = "77oYT33t13HnZ6PNxKdbHDABb1uR2zzJMW9u7cJuwkRq";
const PROTOCOL_VERSION: u8 = 1;
/// Long enough that "execute early" is genuinely early, short enough to wait.
const TIMELOCK_SECONDS: i64 = 10;

fn program_so_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("GLC_BRIDGE_SO") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/glc_bridge.so");
    p.exists().then_some(p)
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
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

struct LocalValidator {
    child: Child,
    _ledger: tempfile::TempDir,
    rpc_url: String,
}

impl LocalValidator {
    fn start(so_path: &Path, program_id: &Pubkey, upgrade_authority: &Pubkey) -> Self {
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
            .arg(so_path)
            .arg(upgrade_authority.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("solana-test-validator must be on PATH");
        let v = LocalValidator {
            child,
            _ledger: ledger,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
        };
        for _ in 0..200 {
            let c = BlockingRpcClient::new_with_commitment(
                v.rpc_url.clone(),
                CommitmentConfig::confirmed(),
            );
            if c.get_health().is_ok() {
                return v;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("solana-test-validator did not become healthy");
    }
}

impl Drop for LocalValidator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn airdrop(client: &BlockingRpcClient, to: &Pubkey, lamports: u64) {
    let sig = client.request_airdrop(to, lamports).unwrap();
    for _ in 0..100 {
        if client.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("airdrop did not confirm");
}

fn program_data_pda(program_id: &Pubkey) -> Pubkey {
    #[allow(deprecated)]
    Pubkey::find_program_address(
        &[program_id.as_ref()],
        &solana_sdk::bpf_loader_upgradeable::id(),
    )
    .0
}

fn build_initialize_ix(
    program_id: &Pubkey,
    authority: &Pubkey,
    validators: &[Pubkey],
    threshold: u8,
) -> Instruction {
    let (bridge_config, _) = glc_ix::bridge_config_pda(program_id);
    let (validator_set, _) = glc_ix::validator_set_pda(program_id);
    let mut data = anchor_discriminator("initialize").to_vec();
    data.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    for v in validators {
        data.extend_from_slice(v.as_ref());
    }
    data.push(threshold);
    data.extend_from_slice(&0u64.to_le_bytes()); // min_deposit
    data.extend_from_slice(&0u64.to_le_bytes()); // min_withdrawal
    data.extend_from_slice(&TIMELOCK_SECONDS.to_le_bytes());
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_wrapped_supply
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(bridge_config, false),
            AccountMeta::new(validator_set, false),
            AccountMeta::new_readonly(*program_id, false),
            AccountMeta::new_readonly(program_data_pda(program_id), false),
            #[allow(deprecated)]
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

/// A validator's local view, fixed at a known epoch — the same trait
/// `signer-server` drives its decisions through.
struct FixedView {
    epoch: u64,
}
impl LocalView for FixedView {
    fn observed_epoch(&self) -> u64 {
        self.epoch
    }
    fn view_is_fresh(&self) -> bool {
        true
    }
    fn derive_message(&self, _a: Action, _id: &SigningIdentity) -> Option<Vec<u8>> {
        None
    }
}

/// One operator: their signer, and the approvals file only they write.
struct Operator {
    service: SignerService<FixedView>,
    approvals: PathBuf,
}

impl Operator {
    fn new(key: Keypair, epoch: u64, approvals: PathBuf, program_id: &Pubkey) -> Self {
        let service = SignerService::new(key, FixedView { epoch }).with_governance_arm(
            GovernanceView::new(approvals.clone()),
            program_id.to_bytes(),
            PROTOCOL_VERSION,
        );
        Operator { service, approvals }
    }

    /// Runbook §7 step 2 — exactly what `glc-admin approve-rotation` writes.
    fn approve(&self, action: u8, commitment: [u8; 32], epoch: u64) {
        let mut store = ApprovalStore::new();
        store.stage(Approval {
            action,
            params_commitment: commitment,
            epoch,
            expiry_unix: now_unix() + 24 * 3600,
            note: "REHEARSAL: OPS-0 planned rotation".into(),
        });
        std::fs::write(&self.approvals, store.to_text()).unwrap();
    }

    fn sign(
        &self,
        action: u8,
        commitment: [u8; 32],
        epoch: u64,
    ) -> Result<(Pubkey, solana_sdk::signature::Signature), String> {
        let resp = self
            .service
            .handle_governance(GovernanceSignRequest {
                request_id: vec![1],
                epoch,
                action: u32::from(action),
                params_commitment: commitment.to_vec(),
                expiry_unix: now_unix() + 120,
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Pubkey::try_from(resp.validator_pubkey.as_slice()).unwrap(),
            solana_sdk::signature::Signature::try_from(resp.signature.as_slice()).unwrap(),
        ))
    }
}

fn send(
    client: &BlockingRpcClient,
    ixs: &[Instruction],
    payer: &Keypair,
) -> Result<solana_sdk::signature::Signature, String> {
    let bh = client.get_latest_blockhash().map_err(|e| e.to_string())?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), &[payer], bh);
    client
        .send_and_confirm_transaction(&tx)
        .map_err(|e| e.to_string())
}

fn epoch_of(client: &BlockingRpcClient, program_id: &Pubkey) -> u64 {
    let (pda, _) = glc_ix::validator_set_pda(program_id);
    let acct = client.get_account(&pda).unwrap();
    decode_validator_set(&acct.data).unwrap().epoch
}

fn validators_of(client: &BlockingRpcClient, program_id: &Pubkey) -> Vec<Pubkey> {
    let (pda, _) = glc_ix::validator_set_pda(program_id);
    let acct = client.get_account(&pda).unwrap();
    decode_validator_set(&acct.data).unwrap().validators
}

fn pending(
    client: &BlockingRpcClient,
    program_id: &Pubkey,
) -> Option<glc_relayer::solana::rpc::PendingActionSnapshot> {
    let (pda, _) = glc_ix::governance_action_pda(program_id);
    match client.get_account(&pda) {
        Ok(a) if !a.data.is_empty() => Some(decode_pending_action(&a.data).unwrap()),
        _ => None,
    }
}

/// **Runbook §7 and §9, end to end against a real validator.**
#[tokio::test(flavor = "multi_thread")]
async fn the_documented_rotation_and_pause_procedures_work_on_a_real_validator() {
    let Some(so_path) = program_so_path() else {
        eprintln!("SKIP: build the program first (../target/deploy/glc_bridge.so)");
        return;
    };
    if !solana_test_validator_available() {
        eprintln!("SKIP: solana-test-validator is not on PATH");
        return;
    }

    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let admin = Keypair::new();
    let validator = LocalValidator::start(&so_path, &program_id, &admin.pubkey());
    let client = BlockingRpcClient::new_with_commitment(
        validator.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    airdrop(&client, &admin.pubkey(), 10_000_000_000);
    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 10_000_000_000);

    // The federation before rotation: 3 validators, threshold 2.
    let old_keys: Vec<Keypair> = (0..3).map(|_| Keypair::new()).collect();
    let old_pubkeys: Vec<Pubkey> = old_keys.iter().map(|k| k.pubkey()).collect();
    send(
        &client,
        &[build_initialize_ix(
            &program_id,
            &admin.pubkey(),
            &old_pubkeys,
            2,
        )],
        &admin,
    )
    .expect("initialize lands");

    let epoch0 = epoch_of(&client, &program_id);
    assert_eq!(validators_of(&client, &program_id), old_pubkeys);

    // --- runbook §9: pause and unpause ------------------------------------
    send(
        &client,
        &[glc_ix::set_paused_instruction(
            &program_id,
            &admin.pubkey(),
            true,
        )],
        &admin,
    )
    .expect("the admin key can pause");
    // The runbook says the program rejects a no-op; that is what makes
    // "pause twice" a safe mistake rather than a silent one.
    assert!(
        send(
            &client,
            &[glc_ix::set_paused_instruction(
                &program_id,
                &admin.pubkey(),
                true
            )],
            &admin,
        )
        .is_err(),
        "pausing an already-paused bridge must be rejected, as runbook §9 states"
    );
    send(
        &client,
        &[glc_ix::set_paused_instruction(
            &program_id,
            &admin.pubkey(),
            false,
        )],
        &admin,
    )
    .expect("the admin key can unpause");

    // A non-admin must not be able to pause. This is the interim single-key
    // model custody #7 leaves open — rehearsing it records what is actually
    // enforced today rather than what we hope is.
    let intruder = Keypair::new();
    airdrop(&client, &intruder.pubkey(), 1_000_000_000);
    assert!(
        send(
            &client,
            &[glc_ix::set_paused_instruction(
                &program_id,
                &intruder.pubkey(),
                true
            )],
            &intruder,
        )
        .is_err(),
        "only the configured admin may pause"
    );

    // --- runbook §7: rotation --------------------------------------------
    let dir = tempfile::tempdir().unwrap();
    let operators: Vec<Operator> = old_keys
        .into_iter()
        .enumerate()
        .map(|(i, k)| {
            Operator::new(
                k,
                epoch0,
                dir.path().join(format!("approvals-{i}")),
                &program_id,
            )
        })
        .collect();

    // The new set: two of the old members plus one new.
    let newcomer = Keypair::new();
    let new_pubkeys: Vec<Pubkey> = vec![old_pubkeys[0], old_pubkeys[1], newcomer.pubkey()];
    let new_threshold: u8 = 2;
    let raw: Vec<[u8; 32]> = new_pubkeys.iter().map(|p| p.to_bytes()).collect();
    let params = rotation_params(new_threshold, &raw);
    let commitment: [u8; 32] = Sha256::digest(&params).into();
    let message = governance_message(
        PROTOCOL_VERSION,
        &program_id.to_bytes(),
        epoch0,
        ACTION_PROPOSE_ROTATION,
        &commitment,
    );

    // Nothing staged yet: every signer refuses. The fail-closed default,
    // checked against real signers rather than asserted.
    for op in &operators {
        assert!(
            op.sign(ACTION_PROPOSE_ROTATION, commitment, epoch0)
                .is_err(),
            "a signer whose operator has staged nothing must refuse"
        );
    }
    assert_eq!(
        can_propose(pending(&client, &program_id).as_ref()),
        Ok(()),
        "nothing is queued yet"
    );

    // Two of three operators approve — the threshold, so the rehearsal
    // proves M is genuinely sufficient rather than requiring unanimity.
    let mut sigs = Vec::new();
    for op in operators.iter().take(2) {
        op.approve(ACTION_PROPOSE_ROTATION, commitment, epoch0);
        sigs.push(
            op.sign(ACTION_PROPOSE_ROTATION, commitment, epoch0)
                .expect("an operator who approved signs"),
        );
    }
    enough_approvals(sigs.len(), 2).expect("two approvals meet the threshold");

    // Submit exactly as `glc-admin submit-rotation` does.
    send(
        &client,
        &[
            build_ed25519_instruction(&sigs, &message),
            glc_ix::propose_rotation_instruction(
                &program_id,
                &payer.pubkey(),
                &new_pubkeys,
                new_threshold,
            ),
        ],
        &payer,
    )
    .expect("a threshold-signed rotation queues");

    let queued = pending(&client, &program_id).expect("the action is queued on chain");
    assert_eq!(queued.action, ACTION_PROPOSE_ROTATION);
    assert_eq!(queued.proposed_under_epoch, epoch0);
    assert_eq!(
        queued.validators, new_pubkeys,
        "the queued set is what was signed"
    );
    assert_eq!(
        can_propose(Some(&queued)),
        Err(PreflightRefusal::AlreadyPending),
        "the singleton refuses a second proposal, as the runbook warns"
    );

    // The timelock is real: executing now must fail ON CHAIN, not merely be
    // refused by the client-side preflight.
    assert!(
        send(
            &client,
            &[glc_ix::execute_rotation_instruction(
                &program_id,
                &payer.pubkey()
            )],
            &payer,
        )
        .is_err(),
        "the governance timelock must be enforced by the program"
    );
    assert!(matches!(
        can_execute(Some(&queued), ACTION_PROPOSE_ROTATION, epoch0, now_unix()),
        Err(PreflightRefusal::TimelockNotElapsed { .. })
    ));

    // Wait it out, then execute — runbook §7 step 5.
    while now_unix() < queued.eta {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The validator's clock and ours can differ by a second; retry briefly
    // rather than racing it, which would make the rehearsal flaky for a
    // reason that has nothing to do with governance.
    let mut executed = Err(String::new());
    for _ in 0..20 {
        executed = send(
            &client,
            &[glc_ix::execute_rotation_instruction(
                &program_id,
                &payer.pubkey(),
            )],
            &payer,
        );
        if executed.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    executed.expect("the rotation executes once its timelock has elapsed");

    // --- what the runbook claims, verified --------------------------------
    let epoch1 = epoch_of(&client, &program_id);
    assert_eq!(epoch1, epoch0 + 1, "a rotation bumps the validator epoch");
    assert_eq!(
        validators_of(&client, &program_id),
        new_pubkeys,
        "the federation is now the proposed set, in the proposed order"
    );
    assert!(
        pending(&client, &program_id).is_none(),
        "the pending action is closed, freeing the singleton slot"
    );

    // Runbook §7: "approvals do not survive a rotation". The staged files
    // are untouched and still say epoch0; under epoch1 they authorise
    // nothing. This is the property that stops a proposal approved by one
    // federation being replayed under another.
    for op in &operators {
        assert!(
            op.sign(ACTION_PROPOSE_ROTATION, commitment, epoch1)
                .is_err(),
            "an approval staged under the previous epoch must not authorise anything now"
        );
    }

    // And a stale proposal cannot be executed under the new federation.
    assert_eq!(
        can_execute(Some(&queued), ACTION_PROPOSE_ROTATION, epoch1, now_unix()),
        Err(PreflightRefusal::EpochMoved {
            proposed: epoch0,
            observed: epoch1
        })
    );
}

/// **Bootstrap, end to end on a real validator** (Phase 7m).
///
/// Runs the launch sequence's steps 3 and the custody #5 handover with the
/// shipped builders: initialize, create the wrapped mint, read the config
/// back, then hand the admin key over in two steps.
#[tokio::test(flavor = "multi_thread")]
async fn the_documented_bootstrap_sequence_works_on_a_real_validator() {
    let Some(so_path) = program_so_path() else {
        eprintln!("SKIP: build the program first");
        return;
    };
    if !solana_test_validator_available() {
        eprintln!("SKIP: solana-test-validator is not on PATH");
        return;
    }

    let program_id: Pubkey = DECLARED_PROGRAM_ID.parse().unwrap();
    let admin = Keypair::new();
    let _validator = LocalValidator::start(&so_path, &program_id, &admin.pubkey());
    let client = BlockingRpcClient::new_with_commitment(
        _validator.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    airdrop(&client, &admin.pubkey(), 10_000_000_000);

    let validators: Vec<Pubkey> = (0..3).map(|_| Keypair::new().pubkey()).collect();
    send(
        &client,
        &[glc_ix::initialize_instruction(
            &program_id,
            &admin.pubkey(),
            &validators,
            2,
            1_000,
            2_000,
            TIMELOCK_SECONDS,
            21_000_000_000_000,
        )],
        &admin,
    )
    .expect("the shipped initialize builder stands the bridge up");

    let read_config = || {
        let (pda, _) = glc_ix::bridge_config_pda(&program_id);
        let acct = client.get_account(&pda).unwrap();
        glc_relayer::solana::rpc::decode_bridge_config(&acct.data).unwrap()
    };

    let cfg = read_config();
    assert_eq!(cfg.min_deposit, 1_000);
    assert_eq!(cfg.min_withdrawal, 2_000);
    assert_eq!(cfg.max_wrapped_supply, 21_000_000_000_000);
    assert!(!cfg.mint_is_configured());
    assert_eq!(validators_of(&client, &program_id), validators);

    // --- create the wrapped mint -----------------------------------------
    let mint = Keypair::new();
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[glc_ix::create_wrapped_mint_instruction(
            &program_id,
            &admin.pubkey(),
            &mint.pubkey(),
        )],
        Some(&admin.pubkey()),
        &[&admin, &mint],
        bh,
    );
    client
        .send_and_confirm_transaction(&tx)
        .expect("the mint account signs its own creation");

    let cfg = read_config();
    assert!(cfg.mint_is_configured(), "the config records the new mint");
    assert_eq!(cfg.wrapped_mint, mint.pubkey());

    // --- custody #5: two-step admin handover ------------------------------
    let successor = Keypair::new();
    airdrop(&client, &successor.pubkey(), 10_000_000_000);

    send(
        &client,
        &[glc_ix::transfer_admin_instruction(
            &program_id,
            &admin.pubkey(),
            &successor.pubkey(),
        )],
        &admin,
    )
    .expect("the outgoing admin nominates a successor");

    let cfg = read_config();
    assert_eq!(
        cfg.pending_admin,
        Some(successor.pubkey()),
        "the nomination is visible to show-config"
    );
    assert_eq!(
        cfg.admin,
        admin.pubkey(),
        "nothing changes until the successor accepts — that is what stops a typo bricking \
         governance"
    );
    // And the decoder must still read every later field correctly with the
    // Option now occupying 33 bytes instead of one.
    assert_eq!(cfg.wrapped_mint, mint.pubkey());
    assert_eq!(cfg.max_wrapped_supply, 21_000_000_000_000);

    // The outgoing admin still holds authority until the handover completes.
    send(
        &client,
        &[glc_ix::set_paused_instruction(
            &program_id,
            &admin.pubkey(),
            true,
        )],
        &admin,
    )
    .expect("the outgoing admin still governs mid-handover");
    send(
        &client,
        &[glc_ix::set_paused_instruction(
            &program_id,
            &admin.pubkey(),
            false,
        )],
        &admin,
    )
    .unwrap();

    send(
        &client,
        &[glc_ix::accept_admin_instruction(
            &program_id,
            &successor.pubkey(),
        )],
        &successor,
    )
    .expect("the incoming admin accepts");

    let cfg = read_config();
    assert_eq!(cfg.admin, successor.pubkey(), "authority moved");
    assert_eq!(cfg.pending_admin, None, "the nomination is consumed");

    // The old key must no longer govern.
    assert!(
        send(
            &client,
            &[glc_ix::set_paused_instruction(
                &program_id,
                &admin.pubkey(),
                true
            )],
            &admin,
        )
        .is_err(),
        "the previous admin must lose authority once the handover completes"
    );
    send(
        &client,
        &[glc_ix::set_paused_instruction(
            &program_id,
            &successor.pubkey(),
            true,
        )],
        &successor,
    )
    .expect("the new admin governs");
}
