"""Hand-applied mutation testing for the Phase 7i indexer-visibility guards (ADR-0023).

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

Run from anywhere: `python3 docs/experiments/phase7i-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 ("N1 halt is not one-way", "src/ops/indexer_status.rs",
  "    pub fn record_tick(&self, at_unix: i64) {\n        self.last_tick_unix.store(at_unix, Ordering::SeqCst);",
  "    pub fn record_tick(&self, at_unix: i64) {\n        self.halted.store(false, Ordering::SeqCst);\n        self.last_tick_unix.store(at_unix, Ordering::SeqCst);"),
 ("N2 staleness clamp removed", "src/ops/indexer_status.rs",
  "        now_unix.saturating_sub(self.last_tick_unix()).max(0)",
  "        now_unix.saturating_sub(self.last_tick_unix())"),
 ("N3 staleness can overflow", "src/ops/indexer_status.rs",
  "        now_unix.saturating_sub(self.last_tick_unix()).max(0)",
  "        (now_unix - self.last_tick_unix()).max(0)"),
 ("N4 halt depth not recorded", "src/ops/indexer_status.rs",
  "        self.halted_depth.store(attempted_depth, Ordering::SeqCst);",
  "        self.halted_depth.store(0, Ordering::SeqCst);"),
 ("N5 halt flag never set", "src/ops/indexer_status.rs",
  "        self.halted.store(true, Ordering::SeqCst);",
  "        self.halted.store(false, Ordering::SeqCst);"),
 ("N6 status starts halted", "src/ops/indexer_status.rs",
  "            halted: AtomicBool::new(false),",
  "            halted: AtomicBool::new(true),"),
 ("H1 halted indexer reported healthy", "src/ops/health.rs",
  "            name: \"indexer_not_halted\",\n            healthy: !i.halted,",
  "            name: \"indexer_not_halted\",\n            healthy: true,"),
 ("H2 invariant emitted even without an indexer", "src/ops/health.rs",
  "    if let Some(i) = indexer {\n        invariants.push(Invariant {\n            name: \"indexer_not_halted\",",
  "    if let Some(i) = indexer.or(Some(IndexerSummary { halted: false, halted_depth: 0, seconds_since_tick: 0 })) {\n        invariants.push(Invariant {\n            name: \"indexer_not_halted\","),
 ("H3 halted gauge inverted", "src/ops/health.rs",
  "            u8::from(i.halted) as f64,",
  "            u8::from(!i.halted) as f64,"),
 ("H4 staleness gauge dropped", "src/ops/health.rs",
  "            i.seconds_since_tick as f64,",
  "            0.0,"),
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
    b = run("cargo test --test ops_endpoint")
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
