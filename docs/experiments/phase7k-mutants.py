"""Hand-applied mutation testing for the Phase 7k auditor and reorg-warning guards (ADR-0025).

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

Run from anywhere: `python3 docs/experiments/phase7k-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- ops::audit -------------------------------------------------------
 ("A1 self-consistency check removed", "src/ops/audit.rs",
  "    if actual.as_slice() != c.message_hash.as_slice() {",
  "    if false && actual.as_slice() != c.message_hash.as_slice() {"),
 ("A2 recompute check removed", "src/ops/audit.rs",
  "    if recomputed.as_slice() != c.canonical_message.as_slice() {",
  "    if false && recomputed.as_slice() != c.canonical_message.as_slice() {"),
 ("A3 field naming always reports the first field", "src/ops/audit.rs",
  "    for (start, end, name) in FIELDS {\n        let a = recomputed.get(start..end);\n        let b = stored.get(start..end);\n        if a != b {\n            return name;\n        }\n    }",
  "    for (_start, _end, name) in FIELDS {\n        return name;\n    }"),
 ("A4 truncated message slicing panics instead of reporting", "src/ops/audit.rs",
  "        let a = recomputed.get(start..end);\n        let b = stored.get(start..end);",
  "        let a = Some(&recomputed[start..end]);\n        let b = Some(&stored[start..end]);"),
 ("A5 payout self-consistency removed", "src/ops/audit.rs",
  "    if payout_commitment(&p.intent_bytes).as_slice() != p.commitment_hash.as_slice() {",
  "    if false && payout_commitment(&p.intent_bytes).as_slice() != p.commitment_hash.as_slice() {"),
 ("A6 payout recompute check removed", "src/ops/audit.rs",
  "    if recomputed != p.intent_bytes {",
  "    if false && recomputed != p.intent_bytes {"),
 ("A7 missing inputs silently skipped", "src/ops/audit.rs",
  "    if inputs.is_empty() {\n        return Some(Finding::PayoutInputsMissing {\n            withdrawal_index: p.withdrawal_index,\n        });\n    }",
  "    if inputs.is_empty() {\n        return None;\n    }"),
 ("A8 is_clean ignores findings", "src/ops/audit.rs",
  "    pub fn is_clean(&self) -> bool {\n        self.findings.is_empty()\n    }",
  "    pub fn is_clean(&self) -> bool {\n        true\n    }"),
 ("A9 integrity_check failure not reported", "src/ops/audit.rs",
  "    if output == \"ok\" {\n        None",
  "    if true {\n        None"),
 ("A10 claims never walked", "src/ops/audit.rs",
  "    for c in db.all_claim_artifacts()? {\n        report.claims_checked += 1;",
  "    for c in db.all_claim_artifacts()?.into_iter().take(0) {\n        report.claims_checked += 1;"),
 ("A11 change address defaults instead of reporting", "src/ops/audit.rs",
  "            Err(_) => {\n                return Some(Finding::PayoutChangeAddressUndecodable {\n                    withdrawal_index: p.withdrawal_index,\n                })\n            }",
  "            Err(_) => [0u8; 20],"),
 # --- ops::indexer_status (reorg warning) -----------------------------
 ("R1 deepest reorg replaced by most recent", "src/ops/indexer_status.rs",
  "        self.deepest_reorg.fetch_max(depth, Ordering::SeqCst);",
  "        self.deepest_reorg.store(depth, Ordering::SeqCst);"),
 ("R2 reorg depth never recorded", "src/ops/indexer_status.rs",
  "        self.deepest_reorg.fetch_max(depth, Ordering::SeqCst);",
  "        let _ = depth;"),
 ("R3 configured ceiling never recorded", "src/ops/indexer_status.rs",
  "        self.max_reorg_depth.store(depth, Ordering::SeqCst);",
  "        let _ = depth;"),
 # --- ops::health (gauges) --------------------------------------------
 ("H5 deepest-reorg gauge dropped", "src/ops/health.rs",
  "            i.deepest_reorg as f64,",
  "            0.0,"),
 ("H6 ceiling gauge dropped", "src/ops/health.rs",
  "            i.max_reorg_depth as f64,",
  "            0.0,"),
 ("H7 a deep reorg wrongly made a breach", "src/ops/health.rs",
  "            healthy: !i.halted,",
  "            healthy: !i.halted && i.deepest_reorg == 0,"),
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
    a = run("cargo test --lib -- ops::")
    # -p only resolves from the repo root: the relayer is a SEPARATE
    # workspace (ADR-0001). Running it from ROOT silently exits non-zero and
    # every mutant looks "broken", which is how I6 first hid.
    b = run("cargo test --test offline_audit")
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
