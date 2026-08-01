"""Hand-applied mutation testing for the Phase 7l signature-grant audit records (ADR-0026).

Each entry replaces one guard with a weakened form and checks that the test
suite fails. A mutant that SURVIVES is a guard nothing tests.

Covers the pre-submission checks (ops::preflight) and the account decoder
(solana::rpc::decode_pending_action) added in Phase 7i-1.

Two traps this harness fell into first, both of which made mutants look
killed-or-clean when they were neither:

  * `cargo test --lib a b c` is a USAGE ERROR, not three filters. It exits
    non-zero having run nothing. Filters go after `--`.
  * Restoring the file with `shutil.move` gives it the BACKUP's mtime, which
    is older than the artifact built from the mutant — so cargo keeps the
    mutated build and the next run reports nonsense. Hence the `os.utime`.

A mutation harness that reports everything killed for mechanical reasons is
worse than no harness at all, so both are guarded here rather than
remembered.

Run from anywhere: `python3 docs/experiments/phase7l-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- the call sites: deleting any one must fail something --------------
 ("G1 mint grant not recorded", "src/p2p/service.rs",
  "            audit_log::record(\n                Granted::Mint { txid, vout: *vout },",
  "            let _unused = (\n                Granted::Mint { txid, vout: *vout },"),
 ("G2 payout grant not recorded", "src/p2p/service.rs",
  "                audit_log::record(\n                    Granted::Payout {",
  "                let _unused = (\n                    Granted::Payout {"),
 ("G3 completion grant not recorded", "src/p2p/service.rs",
  "        audit_log::record(\n            Granted::Completion {",
  "        let _unused = (\n            Granted::Completion {"),
 ("G4 governance grant not recorded", "src/p2p/service.rs",
  "        audit_log::record(\n            Granted::Governance {",
  "        let _unused = (\n            Granted::Governance {"),
 ("G5 sweep grant not recorded", "src/p2p/service.rs",
  "                audit_log::record(\n                    Granted::Sweep {",
  "                let _unused = (\n                    Granted::Sweep {"),
 # --- the record's content ---------------------------------------------
 ("L1 everything logged at info, hiding governance and sweeps", "src/p2p/audit_log.rs",
  "        matches!(self, Granted::Governance { .. } | Granted::Sweep { .. })",
  "        false"),
 ("L2 everything logged at warn, burying routine traffic", "src/p2p/audit_log.rs",
  "        matches!(self, Granted::Governance { .. } | Granted::Sweep { .. })",
  "        true"),
 ("L3 event name changed, breaking every operator filter", "src/p2p/audit_log.rs",
  'pub const EVENT: &str = "signature_granted";',
  'pub const EVENT: &str = "sig_ok";'),
 ("L4 mint identity drops the vout", "src/p2p/audit_log.rs",
  'format!("{}:{vout}", crate::glc::hex::encode(*txid))',
  'crate::glc::hex::encode(*txid)'),
 ("L5 payout identity drops the quorum attempt", "src/p2p/audit_log.rs",
  'format!("withdrawal {withdrawal_index} attempt {quorum_attempt}")',
  'format!("withdrawal {withdrawal_index}")'),
 ("L6 governance identity drops the epoch", "src/p2p/audit_log.rs",
  'format!("action {action} under epoch {epoch}")',
  'format!("action {action}")'),
 ("L7 sweep identity drops the amount", "src/p2p/audit_log.rs",
  'format!("{inputs} inputs totalling {swept_atomic} atomic")',
  'format!("{inputs} inputs")'),
 ("L8 action names collapse", "src/p2p/audit_log.rs",
  'Granted::Payout { .. } => "payout",',
  'Granted::Payout { .. } => "mint",'),
 ("L9 validator identity omitted", "src/p2p/audit_log.rs",
  "    let validator = crate::glc::hex::encode(validator);",
  "    let validator = String::new();"),
 # --- the sweep amount must be real, not a placeholder ------------------
 ("S7 sweep reports a placeholder amount", "src/p2p/sweep_view.rs",
  "            swept_atomic: plan.swept_atomic,",
  "            swept_atomic: 0,"),
 ("S8 sweep reports a placeholder input count", "src/p2p/sweep_view.rs",
  "            inputs: plan.inputs.len(),",
  "            inputs: 0,"),
]

def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)

survived, killed, broken = [], [], []
for name, path, old, new in MUTANTS:
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if old not in src:
        broken.append((name, "pattern not found"))
        continue
    shutil.copy(full, full + ".bak")
    open(full, "w").write(src.replace(old, new, 1))
    a = run("cargo test --lib -- p2p::")
    # -p only resolves from the repo root: the relayer is a SEPARATE
    # workspace (ADR-0001). Running it from ROOT silently exits non-zero and
    # every mutant looks "broken", which is how I6 first hid.
    # ALL suites that assert on a grant record. The payout and completion
    # tests live beside their fixtures, so running only signature_audit_log
    # left G2/G3 looking like survivors when they were merely unexercised —
    # the third time in this project a harness has misreported a mutant.
    b = run("cargo test --test signature_audit_log --test payout_signer_view "
            "--test completion_attestation")
    out = a.stdout + a.stderr + b.stdout + b.stderr
    shutil.move(full + ".bak", full)
    os.utime(full, None)  # restore bumps mtime; otherwise cargo keeps the mutant build
    oks = out.count("test result: ok")
    if oks < 4:
        if "FAILED" in out or "panicked" in out:
            killed.append(name)
        else:
            broken.append((name, "did not compile or run"))
    else:
        survived.append(name)
    print(f"{'KILLED  ' if name in killed else 'SURVIVED' if name in survived else 'BROKEN  '} {name}", flush=True)

print("\n=== summary ===")
print(f"killed:   {len(killed)}")
print(f"survived: {len(survived)}")
for s in survived: print("  SURVIVED:", s)
for b in broken: print("  BROKEN:", b)
