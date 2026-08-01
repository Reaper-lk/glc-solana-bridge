"""Hand-applied mutation testing for the Phase 7i-0 guards (ADR-0021 §7).

Each entry replaces one guard with a weakened form and checks that the test
suite fails. A mutant that SURVIVES is a guard nothing tests.

Result: 23/23 killed. S3 (the sweep equivocation guard) survived the first
run and a test was added for it.

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

Run from anywhere: `python3 docs/experiments/phase7i0-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- governance_view -------------------------------------------------
 ("G1 is_governance_action always true", "src/p2p/governance_view.rs",
  "        if !is_governance_action(action) {\n            return Err(GovernanceRefusal::NotAGovernanceAction(action));\n        }",
  "        if false {\n            return Err(GovernanceRefusal::NotAGovernanceAction(action));\n        }"),
 ("G2 requested-epoch check removed", "src/p2p/governance_view.rs",
  "        if requested_epoch != observed_epoch {",
  "        if false && requested_epoch != observed_epoch {"),
 ("G3 commitment equality removed", "src/p2p/governance_view.rs",
  "        if approval.params_commitment != *params_commitment {",
  "        if false && approval.params_commitment != *params_commitment {"),
 ("G4 approval-epoch check removed", "src/p2p/governance_view.rs",
  "        if approval.epoch != observed_epoch {",
  "        if false && approval.epoch != observed_epoch {"),
 ("G5 expiry boundary off by one", "src/p2p/governance_view.rs",
  "        if now_unix > approval.expiry_unix {",
  "        if now_unix > approval.expiry_unix + 1 {"),
 ("G6 equivocation guard removed", "src/p2p/governance_view.rs",
  "            Some(_) => Err(GovernanceRefusal::AlreadySignedAnother { action }),",
  "            Some(_) => Ok(()),"),
 # --- sweep_view ------------------------------------------------------
 ("S1 sweep commitment equality removed", "src/p2p/sweep_view.rs",
  "        if approval.commitment != commitment {",
  "        if false && approval.commitment != commitment {"),
 ("S2 sweep expiry removed", "src/p2p/sweep_view.rs",
  "        if now_unix > approval.expiry_unix {",
  "        if false && now_unix > approval.expiry_unix {"),
 ("S3 sweep equivocation guard removed", "src/p2p/sweep_view.rs",
  "                Some(_) => return Err(SweepRefusal::AlreadySignedAnother),",
  "                Some(_) => {}"),
 ("S4 fee ceiling removed", "src/p2p/sweep_view.rs",
  "        if fee > ceiling {",
  "        if false && fee > ceiling {"),
 ("S5 unknown-input check accepts anything", "src/p2p/sweep_view.rs",
  "                .find(|u| u.txid == inp.prev_txid && u.vout as u32 == inp.prev_vout)",
  "                .find(|_u| true)"),
 ("S6 output-exceeds-inputs underflow allowed", "src/p2p/sweep_view.rs",
  "        let fee = total_in\n            .checked_sub(out.value)\n            .ok_or(SweepRefusal::OutputExceedsInputs)?;",
  "        let fee = total_in.saturating_sub(out.value);"),
 # --- sweep (pure) ----------------------------------------------------
 ("P1 destination-is-source check removed", "src/withdrawal/sweep.rs",
  "    if dest_hash160 == source_hash160 {",
  "    if false && dest_hash160 == source_hash160 {"),
 ("P2 single-output check removed", "src/withdrawal/sweep.rs",
  "    if tx.outputs.len() != 1 {",
  "    if false && tx.outputs.len() != 1 {"),
 ("P3 destination script check removed", "src/withdrawal/sweep.rs",
  "    if out.script_pubkey != plan.dest_script_pubkey {",
  "    if false && out.script_pubkey != plan.dest_script_pubkey {"),
 ("P4 output amount check removed", "src/withdrawal/sweep.rs",
  "    if out.value != plan.swept_atomic {",
  "    if false && out.value != plan.swept_atomic {"),
 ("P5 pre-signed input accepted", "src/withdrawal/sweep.rs",
  "        if !got.script_sig.is_empty() {",
  "        if false && !got.script_sig.is_empty() {"),
 ("P6 input identity check removed", "src/withdrawal/sweep.rs",
  "        if got.prev_txid != want.txid || u64::from(got.prev_vout) != want.vout as u64 {",
  "        if false {"),
 ("P7 input count check removed", "src/withdrawal/sweep.rs",
  "    if tx.inputs.len() != plan.inputs.len() {",
  "    if false && tx.inputs.len() != plan.inputs.len() {"),
 ("P8 dust check removed", "src/withdrawal/sweep.rs",
  "    if swept < dust_threshold_atomic {",
  "    if false && swept < dust_threshold_atomic {"),
 ("P9 input cap removed", "src/withdrawal/sweep.rs",
  "    if utxos.len() > max_inputs {",
  "    if false && utxos.len() > max_inputs {"),
 ("P10 commitment drops the input set", "src/withdrawal/sweep.rs",
  "        for u in &self.inputs {\n            out.extend_from_slice(&u.txid);\n            out.extend_from_slice(&(u.vout as u32).to_le_bytes());\n            out.extend_from_slice(&u.amount_atomic.to_le_bytes());\n        }",
  "        for _u in &self.inputs {}"),
 ("P11 commitment drops the destination", "src/withdrawal/sweep.rs",
  "        out.extend_from_slice(&self.dest_hash160);\n        out.extend_from_slice(&(self.dest_script_pubkey.len() as u16).to_le_bytes());\n        out.extend_from_slice(&self.dest_script_pubkey);",
  "        out.extend_from_slice(&(self.dest_script_pubkey.len() as u16).to_le_bytes());"),
]

def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, shell=True, capture_output=True, text=True)

survived, killed, broken = [], [], []
for name, path, old, new in MUTANTS:
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if old not in src:
        broken.append((name, "pattern not found"))
        continue
    shutil.copy(full, full + ".bak")
    open(full, "w").write(src.replace(old, new, 1))
    a = run("cargo test --lib -- withdrawal::sweep p2p::sweep_view p2p::governance_view")
    b = run("cargo test --test operator_tooling")
    out = a.stdout + a.stderr + b.stdout + b.stderr
    shutil.move(full + ".bak", full)
    os.utime(full, None)  # restore bumps mtime; otherwise cargo keeps the mutant build
    oks = out.count("test result: ok")
    if oks < 2:
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
