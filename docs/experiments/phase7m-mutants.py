"""Hand-applied mutation testing for the Phase 7m bootstrap tooling (ADR-0027).

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

Run from anywhere: `python3 docs/experiments/phase7m-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- solana::instruction (bootstrap encoding) -------------------------
 ("B1 initialize sorts validators, destroying bitmask order", "src/solana/instruction.rs",
  "    for v in validators {\n        data.extend_from_slice(v.as_ref());\n    }\n    data.push(threshold);\n    data.extend_from_slice(&min_deposit.to_le_bytes());",
  "    let mut sorted: Vec<Pubkey> = validators.to_vec();\n    sorted.sort();\n    for v in &sorted {\n        data.extend_from_slice(v.as_ref());\n    }\n    data.push(threshold);\n    data.extend_from_slice(&min_deposit.to_le_bytes());"),
 ("B2 initialize swaps min_deposit and min_withdrawal", "src/solana/instruction.rs",
  "    data.extend_from_slice(&min_deposit.to_le_bytes());\n    data.extend_from_slice(&min_withdrawal.to_le_bytes());",
  "    data.extend_from_slice(&min_withdrawal.to_le_bytes());\n    data.extend_from_slice(&min_deposit.to_le_bytes());"),
 ("B3 initialize swaps timelock and supply cap", "src/solana/instruction.rs",
  "    data.extend_from_slice(&governance_timelock_seconds.to_le_bytes());\n    data.extend_from_slice(&max_wrapped_supply.to_le_bytes());",
  "    data.extend_from_slice(&max_wrapped_supply.to_le_bytes());\n    data.extend_from_slice(&governance_timelock_seconds.to_le_bytes());"),
 ("B4 the mint no longer signs its own creation", "src/solana/instruction.rs",
  "            AccountMeta::new(*wrapped_mint, true),",
  "            AccountMeta::new(*wrapped_mint, false),"),
 ("B5 program_data derived from the wrong loader", "src/solana/instruction.rs",
  "        &solana_sdk::bpf_loader_upgradeable::id(),",
  "        &system_program::id(),"),
 ("B6 transfer_admin drops the successor", "src/solana/instruction.rs",
  "    data.extend_from_slice(new_admin.as_ref());",
  "    data.extend_from_slice(admin.as_ref());"),
 ("B7 accept_admin signed by the wrong side", "src/solana/instruction.rs",
  "            AccountMeta::new_readonly(*new_admin, true),\n            AccountMeta::new(bridge_config_pda(program_id).0, false),\n        ],\n        data: anchor_discriminator(\"accept_admin\").to_vec(),",
  "            AccountMeta::new_readonly(*new_admin, false),\n            AccountMeta::new(bridge_config_pda(program_id).0, false),\n        ],\n        data: anchor_discriminator(\"accept_admin\").to_vec(),"),
 # --- solana::rpc (BridgeConfig decoding) ------------------------------
 ("C1 pending_admin option tag ignored, offsets fixed", "src/solana/rpc.rs",
  "        1 => (\n            Some(pk(body.get(34..66).ok_or_else(|| need(\"pending admin\"))?)),\n            66usize,\n        ),",
  "        1 => (\n            Some(pk(body.get(34..66).ok_or_else(|| need(\"pending admin\"))?)),\n            34usize,\n        ),"),
 ("C2 invalid option tag silently treated as absent", "src/solana/rpc.rs",
  "        other => {\n            return Err(SolanaRpcError::Malformed(format!(\n                \"bridge config: pending_admin has an invalid Borsh option tag {other}\"\n            )))\n        }",
  "        _ => (None, 34usize),"),
 ("C3 bump byte not skipped before the mint", "src/solana/rpc.rs",
  "    off += 1; // bump\n    let wrapped_mint",
  "    off += 0; // bump\n    let wrapped_mint"),
 ("C4 mint_authority_bump not skipped", "src/solana/rpc.rs",
  "    off += 1; // mint_authority_bump",
  "    off += 0; // mint_authority_bump"),
 ("C5 an unset mint reported as configured", "src/solana/rpc.rs",
  "        self.wrapped_mint != Pubkey::default()",
  "        true"),
 ("C6 paused byte misread", "src/solana/rpc.rs",
  "    let paused = *body.get(off).ok_or_else(|| need(\"paused\"))? != 0;",
  "    let paused = false;"),
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
    a = run("cargo test --lib -- solana::")
    # -p only resolves from the repo root: the relayer is a SEPARATE
    # workspace (ADR-0001). Running it from ROOT silently exits non-zero and
    # every mutant looks "broken", which is how I6 first hid.
    # ALL suites that assert on a grant record. The payout and completion
    # tests live beside their fixtures, so running only signature_audit_log
    # left G2/G3 looking like survivors when they were merely unexercised —
    # the third time in this project a harness has misreported a mutant.
    b = run("cargo test -p glc-bridge --test admin_governance_encoding",
            cwd="/home/reaper/glc-solana-bridge")
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
