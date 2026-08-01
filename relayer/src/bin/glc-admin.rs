//! `glc-admin` — the operator utility (Phase 7i-0).
//!
//! Every recovery and governance procedure in the runbooks is invoked from
//! here. Before this existed, `operator_clear_integrity_halt`,
//! `operator_clear_withdrawal_halt` and `reassign_payout_quorum` were
//! implemented, guarded and audited — and reachable **only from tests**. An
//! operator facing an integrity halt had no supported way to act.
//!
//! A runbook step with no executable form is not a procedure, it is a wish.
//! This binary exists so the Phase 7i runbooks can name real commands.
//!
//! # What it deliberately does not do
//!
//! It holds no validator key, no vault key and no admin key. Recovery
//! commands touch only this operator's own database. Governance and sweep
//! commands *stage an approval* for this operator's own signer. Nothing here
//! can move value or change federation policy on its own.
//!
//! # Every mutating command demands a reason
//!
//! `--note` is mandatory and is recorded in the audit trail. An operator
//! action with no recorded reason is indistinguishable from an intrusion six
//! months later.

use std::path::PathBuf;

use glc_bridge_shared::governance::{
    cancel_params, rotation_params, tvl_raise_params, ACTION_CANCEL_ROTATION,
    ACTION_PROPOSE_ROTATION, ACTION_PROPOSE_TVL_RAISE,
};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

use glc_relayer::glc::db::{Db, DepositState};
use glc_relayer::glc::hex;
use glc_relayer::glc::withdrawal_db::{
    canonical_payout_intent, payout_commitment, WithdrawalState,
};
use glc_relayer::p2p::governance_view::{Approval, ApprovalStore, APPROVAL_TTL_SECONDS};
use glc_relayer::p2p::sweep_view::{SweepApproval, SWEEP_APPROVAL_TTL_SECONDS};
use glc_relayer::withdrawal::config::{RawWithdrawalConfig, WithdrawalConfig};
use glc_relayer::withdrawal::sweep::{plan_sweep, SweepDestination, SweepPlan};

const USAGE: &str = r#"glc-admin — operator utility for recovery, governance and vault sweeps

STATUS
  status                --db PATH

RECOVERY (acts on this operator's own database only)
  clear-deposit-halt    --db PATH --id N --to ReadyForSignature|Failed --note TEXT
  clear-withdrawal-halt --db PATH --index N --to Validated|Failed --note TEXT
  reassign-quorum       --db PATH --index N --quorum a,b --note TEXT

GOVERNANCE (stages an approval for THIS operator's signer)
  approve-rotation      --approvals PATH --epoch N --threshold M --validators A,B,C --note TEXT
  approve-tvl-raise     --approvals PATH --epoch N --new-max ATOMIC --note TEXT
  approve-cancel        --approvals PATH --epoch N --pending-action N --pending-eta N --note TEXT
  list-approvals        --approvals PATH
  revoke-approval       --approvals PATH --action N

VAULT SWEEP (ADR-0014 section 8.7 compromise response)
  sweep-plan            --db PATH --dest-hash160 HEX --dest-address ADDR
  sweep-approve         --db PATH --sweep-approvals PATH --dest-hash160 HEX
                        --dest-address ADDR --commitment HEX --note TEXT
  sweep-revoke          --sweep-approvals PATH

Staging an approval does NOT perform the action. It tells this operator's own
signer that it may sign that one exact proposal. The action happens only once
M operators have each independently done the same.

Vault configuration is read from the environment, exactly as the relayer and
signer read it (GLC_VAULT_REDEEM_SCRIPT_HEX, GLC_VAULT_ADDRESS, ...), so a
sweep is planned against the same validated vault the pipeline uses."#;

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn require(args: &[String], name: &str) -> String {
    match arg(args, name) {
        Some(v) => v,
        None => {
            eprintln!("error: {name} is required\n");
            usage()
        }
    }
}

fn require_note(args: &[String]) -> String {
    let note = require(args, "--note");
    if note.trim().is_empty() {
        eprintln!("error: --note must not be empty — every operator action is audited");
        std::process::exit(2);
    }
    note
}

fn open_db(args: &[String]) -> anyhow::Result<Db> {
    Ok(Db::open(&PathBuf::from(require(args, "--db")))?)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn commitment_of(params: &[u8]) -> [u8; 32] {
    Sha256::digest(params).into()
}

fn env_required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is not set"))
}

/// The same validated vault the relayer and signer load, from the same
/// environment. Deliberately not a separate set of flags: a sweep planned
/// against a vault the pipeline does not agree with is a sweep of the wrong
/// vault.
fn withdrawal_config_from_env() -> anyhow::Result<WithdrawalConfig> {
    let raw = RawWithdrawalConfig {
        vault_redeem_script_hex: env_required("GLC_VAULT_REDEEM_SCRIPT_HEX")?,
        vault_address: env_required("GLC_VAULT_ADDRESS")?,
        change_address: env_required("GLC_VAULT_CHANGE_ADDRESS")?,
        fee_rate_per_kb: env_required("GLC_PAYOUT_FEE_RATE_PER_KB")?.parse()?,
        dust_threshold_atomic: env_required("GLC_PAYOUT_DUST_THRESHOLD_ATOMIC")?.parse()?,
        vault_min_confirmations: env_required("GLC_VAULT_MIN_CONFIRMATIONS")?.parse()?,
        confirmation_depth: env_required("GLC_WITHDRAWAL_CONFIRMATION_DEPTH")?.parse()?,
        max_inputs_per_payout: env_required("GLC_PAYOUT_MAX_INPUTS")?.parse()?,
        reservation_timeout_secs: env_required("GLC_PAYOUT_RESERVATION_TIMEOUT_SECS")?.parse()?,
        discovery_commitment: env_required("GLC_WITHDRAWAL_DISCOVERY_COMMITMENT")?,
        poll_interval_ms: 5_000,
    };
    WithdrawalConfig::validate(raw)
        .map_err(|e| anyhow::anyhow!("invalid withdrawal configuration: {e}"))
}

fn protocol_version_from_env() -> anyhow::Result<u8> {
    Ok(env_required("GLC_PROTOCOL_VERSION")?.parse()?)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1).map(|s| s.as_str()) else {
        usage()
    };

    match cmd {
        "status" => status(&args),
        "clear-deposit-halt" => clear_deposit_halt(&args),
        "clear-withdrawal-halt" => clear_withdrawal_halt(&args),
        "reassign-quorum" => reassign_quorum(&args),
        "approve-rotation" => approve_rotation(&args),
        "approve-tvl-raise" => approve_tvl_raise(&args),
        "approve-cancel" => approve_cancel(&args),
        "list-approvals" => list_approvals(&args),
        "revoke-approval" => revoke_approval(&args),
        "sweep-plan" => sweep_plan(&args),
        "sweep-approve" => sweep_approve(&args),
        "sweep-revoke" => sweep_revoke(&args),
        "-h" | "--help" | "help" => usage(),
        other => {
            eprintln!("error: unknown command {other:?}\n");
            usage()
        }
    }
}

// ------------------------------------------------------------------ status

/// What an operator wants first in an incident: what is stuck, and why.
fn status(args: &[String]) -> anyhow::Result<()> {
    let db = open_db(args)?;

    println!("deposits by state:");
    for (state, n) in db.deposit_counts_by_state()? {
        println!("  {state:<20} {n}");
    }
    println!("\nwithdrawals by state:");
    for (state, n) in db.withdrawal_counts_by_state()? {
        println!("  {state:<20} {n}");
    }
    let (utxo_count, utxo_total) = db.vault_utxo_stats()?;
    println!("\nvault: {utxo_count} available outputs, {utxo_total} atomic units");

    let halted = db.candidates_by_state(DepositState::IntegrityHalted)?;
    if !halted.is_empty() {
        println!("\nHALTED DEPOSITS — each needs an explicit operator decision:");
        for d in &halted {
            println!(
                "  id={} txid={} vout={} amount={}\n    reason: {}",
                d.id,
                d.txid_hex,
                d.vout,
                d.amount_atomic,
                d.failure_reason.as_deref().unwrap_or("(none recorded)")
            );
        }
    }
    let halted_w = db.withdrawals_by_state(WithdrawalState::IntegrityHalted)?;
    if !halted_w.is_empty() {
        println!("\nHALTED WITHDRAWALS:");
        for w in &halted_w {
            println!(
                "  index={} amount={}\n    reason: {}",
                w.withdrawal_index,
                w.amount_atomic,
                w.failure_reason.as_deref().unwrap_or("(none recorded)")
            );
        }
    }
    if halted.is_empty() && halted_w.is_empty() {
        println!("\nno integrity halts");
    }
    Ok(())
}

// ---------------------------------------------------------------- recovery

fn clear_deposit_halt(args: &[String]) -> anyhow::Result<()> {
    let mut db = open_db(args)?;
    let id: i64 = require(args, "--id").parse()?;
    let to = DepositState::parse(&require(args, "--to"))?;
    let note = require_note(args);

    // Show the record before altering it. An operator acting under pressure
    // deserves to see what they are about to change.
    let before = db
        .get_by_id(id)?
        .ok_or_else(|| anyhow::anyhow!("no deposit with id {id}"))?;
    println!(
        "deposit {id}: {} -> {}\n  txid={} vout={} amount={}\n  halt reason: {}",
        before.state.as_str(),
        to.as_str(),
        before.txid_hex,
        before.vout,
        before.amount_atomic,
        before.failure_reason.as_deref().unwrap_or("(none)")
    );

    db.operator_clear_integrity_halt(id, to, &note, now_unix())?;
    println!("cleared. The halt record is preserved; the recovery was appended beside it.");
    Ok(())
}

fn clear_withdrawal_halt(args: &[String]) -> anyhow::Result<()> {
    let mut db = open_db(args)?;
    let index: i64 = require(args, "--index").parse()?;
    let to = WithdrawalState::parse(&require(args, "--to"))?;
    let note = require_note(args);

    let before = db
        .get_withdrawal(index)?
        .ok_or_else(|| anyhow::anyhow!("no withdrawal with index {index}"))?;
    println!(
        "withdrawal {index}: {} -> {}\n  amount={}\n  halt reason: {}",
        before.state.as_str(),
        to.as_str(),
        before.amount_atomic,
        before.failure_reason.as_deref().unwrap_or("(none)")
    );

    db.operator_clear_withdrawal_halt(index, to, &note, now_unix())?;
    println!("cleared. The halt record is preserved.");
    Ok(())
}

/// Re-designates the signing quorum for a payout whose designated signers
/// cannot sign (ADR-0015).
///
/// The new quorum is given explicitly rather than derived: the operator is
/// the one who knows *which* signer is unavailable, and an automatic
/// substitution is exactly what ADR-0015 forbids.
fn reassign_quorum(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let mut db = open_db(args)?;
    let index: i64 = require(args, "--index").parse()?;
    let note = require_note(args);
    let new_quorum: Vec<u8> = require(args, "--quorum")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u8>().map_err(|e| anyhow::anyhow!("{s:?}: {e}")))
        .collect::<anyhow::Result<_>>()?;
    cfg.vault
        .validate_quorum(&new_quorum)
        .map_err(|e| anyhow::anyhow!("the proposed quorum is not valid for this vault: {e}"))?;

    let payout = db
        .get_payout(index)?
        .ok_or_else(|| anyhow::anyhow!("no payout for withdrawal {index}"))?;
    if payout.signed_tx_hex.is_some() {
        // A signed payout has a txid that may already be in a mempool.
        // Re-designating would produce a second, conflicting transaction.
        anyhow::bail!(
            "withdrawal {index} is already signed (txid {}) — rebroadcast it rather than \
             reassigning; reassignment changes the txid",
            payout.txid_hex.as_deref().unwrap_or("unknown")
        );
    }
    let w = db
        .get_withdrawal(index)?
        .ok_or_else(|| anyhow::anyhow!("no withdrawal with index {index}"))?;
    let inputs = db.payout_inputs(index)?;
    let attempt = payout.quorum_attempt + 1;

    println!(
        "withdrawal {index}: attempt {} -> {attempt}\n  quorum {:?} -> {new_quorum:?}\n  \
         payout {} fee {} change {}",
        payout.quorum_attempt,
        payout.quorum_indices,
        payout.payout_atomic,
        payout.fee_atomic,
        payout.change_atomic
    );
    println!(
        "\nNOTE: reassignment changes the payout txid (ADR-0015). Every operator must reassign\n\
         to the same attempt and the same quorum before signatures can be collected."
    );

    // The intent is rebuilt exactly as the executor builds it: same inputs,
    // same amounts, same destination — only the quorum and attempt change.
    // The unsigned transaction is unchanged, because the quorum affects the
    // scriptSig, not the outputs.
    let change_hash160 = if payout.change_atomic > 0 {
        cfg.change_hash160
    } else {
        [0u8; 20]
    };
    let intent = canonical_payout_intent(
        w.protocol_version,
        index,
        &cfg.vault.script_hash160,
        &w.glc_address_hash160,
        payout.payout_atomic,
        payout.fee_atomic,
        payout.change_atomic,
        &change_hash160,
        attempt,
        &new_quorum,
        &inputs,
    );
    let next = db.reassign_payout_quorum(
        index,
        &new_quorum,
        &payout_commitment(&intent),
        &intent,
        &payout.unsigned_tx_hex,
        &note,
        now_unix(),
    )?;
    println!("reassigned to attempt {next}");
    Ok(())
}

// -------------------------------------------------------------- governance

fn stage(args: &[String], approval: Approval) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let mut store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    store.stage(approval.clone());
    std::fs::write(&path, store.to_text())?;

    println!(
        "staged approval for action {} under epoch {}\n  commitment: {}\n  expires:    {} (in {} hours)\n  note:       {}",
        approval.action,
        approval.epoch,
        hex::encode(&approval.params_commitment),
        approval.expiry_unix,
        APPROVAL_TTL_SECONDS / 3600,
        approval.note
    );
    println!(
        "\nThis authorises THIS operator's signer to sign that one exact proposal. The action\n\
         takes effect only once M operators have each done the same, and — for rotations and\n\
         raises — the governance timelock has elapsed."
    );
    Ok(())
}

fn approve_rotation(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let threshold: u8 = require(args, "--threshold").parse()?;
    let validators: Vec<[u8; 32]> = require(args, "--validators")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Pubkey>()
                .map(|p| p.to_bytes())
                .map_err(|e| anyhow::anyhow!("{s:?} is not a pubkey: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;
    if threshold == 0 || usize::from(threshold) > validators.len() {
        anyhow::bail!(
            "threshold {threshold} is impossible for {} validators",
            validators.len()
        );
    }
    // Order is significant — it fixes each validator's bitmask index — so it
    // is echoed back for the operator to check against the other operators'.
    println!("rotation: threshold {threshold} of {}", validators.len());
    for (i, v) in validators.iter().enumerate() {
        println!("  [{i}] {}", Pubkey::from(*v));
    }
    stage(
        args,
        Approval {
            action: ACTION_PROPOSE_ROTATION,
            params_commitment: commitment_of(&rotation_params(threshold, &validators)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

fn approve_tvl_raise(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let new_max: u64 = require(args, "--new-max").parse()?;
    if new_max == 0 {
        anyhow::bail!("a wrapped-supply cap of zero is never valid");
    }
    println!("TVL raise: new ceiling {new_max} atomic units");
    stage(
        args,
        Approval {
            action: ACTION_PROPOSE_TVL_RAISE,
            params_commitment: commitment_of(&tvl_raise_params(new_max)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

fn approve_cancel(args: &[String]) -> anyhow::Result<()> {
    let epoch: u64 = require(args, "--epoch").parse()?;
    let pending_action: u8 = require(args, "--pending-action").parse()?;
    let pending_eta: i64 = require(args, "--pending-eta").parse()?;
    println!("cancel: pending action {pending_action}, eta {pending_eta}");
    stage(
        args,
        Approval {
            action: ACTION_CANCEL_ROTATION,
            params_commitment: commitment_of(&cancel_params(pending_action, pending_eta)),
            epoch,
            expiry_unix: now_unix() + APPROVAL_TTL_SECONDS,
            note: require_note(args),
        },
    )
}

const GOVERNANCE_ACTIONS: [u8; 3] = [
    ACTION_PROPOSE_ROTATION,
    ACTION_CANCEL_ROTATION,
    ACTION_PROPOSE_TVL_RAISE,
];

fn list_approvals(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    if store.is_empty() {
        println!("no approvals staged — this signer will refuse every governance request");
        return Ok(());
    }
    let now = now_unix();
    for action in GOVERNANCE_ACTIONS {
        if let Some(a) = store.get(action) {
            println!(
                "action {} epoch {} {} commitment {}\n  note: {}",
                a.action,
                a.epoch,
                if now > a.expiry_unix {
                    "EXPIRED"
                } else {
                    "valid"
                },
                hex::encode(&a.params_commitment),
                a.note
            );
        }
    }
    Ok(())
}

fn revoke_approval(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--approvals"));
    let action: u8 = require(args, "--action").parse()?;
    let store = ApprovalStore::load(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut kept = ApprovalStore::new();
    for a in GOVERNANCE_ACTIONS {
        if a != action {
            if let Some(existing) = store.get(a) {
                kept.stage(existing.clone());
            }
        }
    }
    std::fs::write(&path, kept.to_text())?;
    // The signer re-reads the file on every request, which is exactly so an
    // operator can withdraw consent mid-incident.
    println!("revoked approval for action {action} — effective immediately, no restart needed");
    Ok(())
}

// ------------------------------------------------------------- vault sweep

/// Builds the sweep an operator is about to approve, from this operator's
/// own UTXO rows.
///
/// Every operator runs this independently. If their commitments differ they
/// are looking at different vault contents and must reconcile *before* any
/// of them approves — which is far better than discovering it when the
/// signatures fail to combine.
fn build_plan(args: &[String], cfg: &WithdrawalConfig, db: &Db) -> anyhow::Result<SweepPlan> {
    let dest_hash160 = hex::decode_exact::<20>(&require(args, "--dest-hash160"))
        .map_err(|e| anyhow::anyhow!("--dest-hash160 is not 20 hex bytes: {e}"))?;
    let dest_address = require(args, "--dest-address");

    let utxos = db.available_utxos(cfg.vault_min_confirmations)?;
    let (all_count, all_total) = db.vault_utxo_stats()?;
    if utxos.len() as u64 != all_count {
        // `available_utxos` excludes reserved outputs. Saying so matters:
        // the sweep would be partial, and an operator who believed it was
        // total would leave funds under the key they meant to abandon.
        println!(
            "WARNING: {} of {all_count} vault outputs are reserved for in-flight payouts and\n\
             will NOT be swept. Release or complete them first for a total sweep.",
            all_count.saturating_sub(utxos.len() as u64)
        );
    }

    let plan = plan_sweep(
        cfg.vault.script_hash160,
        SweepDestination::p2sh(dest_hash160, dest_address),
        &utxos,
        cfg.fee_rate_per_kb,
        cfg.dust_threshold_atomic,
        cfg.max_inputs_per_payout,
    )
    .map_err(|e| anyhow::anyhow!("cannot plan this sweep: {e}"))?;

    println!(
        "sweep of vault {}\n  from:   {} ({} outputs, {} atomic total in vault)\n  to:     {} ({})\n  \
         inputs: {}\n  fee:    {}\n  swept:  {}",
        hex::encode(&cfg.vault.script_hash160),
        cfg.vault.address,
        all_count,
        all_total,
        plan.dest_address,
        hex::encode(&plan.dest_hash160),
        plan.inputs.len(),
        plan.fee_atomic,
        plan.swept_atomic
    );
    for u in &plan.inputs {
        println!("    {}:{} {}", u.txid_hex, u.vout, u.amount_atomic);
    }
    Ok(plan)
}

fn sweep_plan(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let protocol_version = protocol_version_from_env()?;
    let db = open_db(args)?;
    let plan = build_plan(args, &cfg, &db)?;
    println!(
        "\ncommitment: {}\n\nCompare this with every other operator BEFORE approving. Differing\n\
         commitments mean differing views of the vault, not a tooling problem.",
        hex::encode(&plan.commitment(protocol_version))
    );
    Ok(())
}

/// Stages a sweep approval — after re-deriving the plan locally and refusing
/// unless it matches the commitment the operator typed.
///
/// `--commitment` is required and is **checked, not trusted**: it is how an
/// operator states what they believe they are approving, and the check is
/// what catches "the number on my screen is not the number on yours".
fn sweep_approve(args: &[String]) -> anyhow::Result<()> {
    let cfg = withdrawal_config_from_env()?;
    let protocol_version = protocol_version_from_env()?;
    let db = open_db(args)?;
    let note = require_note(args);
    let claimed = hex::decode_exact::<32>(&require(args, "--commitment"))
        .map_err(|e| anyhow::anyhow!("--commitment is not 32 hex bytes: {e}"))?;

    let plan = build_plan(args, &cfg, &db)?;
    let actual = plan.commitment(protocol_version);
    if actual != claimed {
        anyhow::bail!(
            "REFUSING TO STAGE: the sweep this operator can build commits to\n  {}\nbut the \
             approval names\n  {}\nThese are different sweeps. Reconcile the vault view with the \
             other operators before approving.",
            hex::encode(&actual),
            hex::encode(&claimed)
        );
    }

    let path = PathBuf::from(require(args, "--sweep-approvals"));
    let approval = SweepApproval {
        commitment: actual,
        expiry_unix: now_unix() + SWEEP_APPROVAL_TTL_SECONDS,
        note,
    };
    std::fs::write(&path, approval.to_text())?;
    println!(
        "\nSTAGED. This signer will now contribute to that ONE sweep, until {} ({} hours).\n\
         It moves the entire available vault. Revoke with `sweep-revoke` if anything changes.",
        approval.expiry_unix,
        SWEEP_APPROVAL_TTL_SECONDS / 3600
    );
    Ok(())
}

fn sweep_revoke(args: &[String]) -> anyhow::Result<()> {
    let path = PathBuf::from(require(args, "--sweep-approvals"));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no sweep approval was staged");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    println!("sweep approval revoked — effective immediately, no restart needed");
    Ok(())
}
