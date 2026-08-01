"""Hand-applied mutation testing for the Phase 7i-1 guards (ADR-0022).

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

Run from anywhere: `python3 docs/experiments/phase7i1-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- ops::preflight ---------------------------------------------------
 ("F1 threshold comparison weakened to <=", "src/ops/preflight.rs",
  "    if collected < usize::from(threshold) {",
  "    if collected + 1 < usize::from(threshold) {"),
 ("F2 approval check removed entirely", "src/ops/preflight.rs",
  "    if collected < usize::from(threshold) {",
  "    if false {"),
 ("F3 singleton proposal guard removed", "src/ops/preflight.rs",
  "        Some(_) => Err(PreflightRefusal::AlreadyPending),",
  "        Some(_) => Ok(()),"),
 ("F4 action-type check removed", "src/ops/preflight.rs",
  "    if p.action != expected_action {",
  "    if false && p.action != expected_action {"),
 ("F5 epoch check removed", "src/ops/preflight.rs",
  "    if p.proposed_under_epoch != observed_epoch {",
  "    if false && p.proposed_under_epoch != observed_epoch {"),
 ("F6 timelock check removed", "src/ops/preflight.rs",
  "    if now_unix < p.eta {",
  "    if false && now_unix < p.eta {"),
 ("F7 timelock boundary off by one", "src/ops/preflight.rs",
  "    if now_unix < p.eta {",
  "    if now_unix < p.eta - 1 {"),
 ("F8 timelock subtraction can wrap", "src/ops/preflight.rs",
  "            remaining: p.eta.saturating_sub(now_unix),",
  "            remaining: p.eta.wrapping_sub(now_unix),"),
 ("F9 cancel targets a fixed action", "src/ops/preflight.rs",
  "    Ok((p.action, p.eta))",
  "    Ok((0x03, p.eta))"),
 ("F10 cancel targets a fixed eta", "src/ops/preflight.rs",
  "    Ok((p.action, p.eta))",
  "    Ok((p.action, 0))"),
 ("F11 nothing-pending treated as executable", "src/ops/preflight.rs",
  "    let p = pending.ok_or(PreflightRefusal::NothingPending)?;\n    if p.action != expected_action {",
  "    let Some(p) = pending else { return Ok(()) };\n    if p.action != expected_action {"),
 # --- solana::rpc::decode_pending_action -------------------------------
 ("D1 eta read from the wrong offset", "src/solana/rpc.rs",
  "        body.get(9..17)\n            .ok_or_else(|| need(\"eta\"))?",
  "        body.get(8..16)\n            .ok_or_else(|| need(\"eta\"))?"),
 ("D2 supply ceiling read at a fixed offset", "src/solana/rpc.rs",
  "    let proposed_max_wrapped_supply = u64::from_le_bytes(\n        body.get(offset..offset + 8)",
  "    let proposed_max_wrapped_supply = u64::from_le_bytes(\n        body.get(87..95)"),
 ("D3 truncated validator list tolerated", "src/solana/rpc.rs",
  "        let pk = body\n            .get(offset..offset + 32)\n            .ok_or_else(|| need(\"a validator\"))?;\n        validators.push(Pubkey::try_from(pk).unwrap());",
  "        let Some(pk) = body.get(offset..offset + 32) else { break };\n        validators.push(Pubkey::try_from(pk).unwrap());"),
 ("D4 discriminator not skipped", "src/solana/rpc.rs",
  "    let body = data\n        .get(DISCRIMINATOR_LEN..)\n        .ok_or_else(|| SolanaRpcError::Malformed(\"account shorter than discriminator\".into()))?;\n    let need = |what: &str| SolanaRpcError::Malformed(format!(\"pending action: missing {what}\"));",
  "    let body = data;\n    let need = |what: &str| SolanaRpcError::Malformed(format!(\"pending action: missing {what}\"));"),
 ("D5 bump byte not skipped", "src/solana/rpc.rs",
  "    // Skip `bump`.\n    offset += 1;",
  "    // Skip `bump`.\n    offset += 0;"),
 # --- solana::instruction (cross-workspace encoding) -------------------
 ("I1 execute paths swap writability", "src/solana/instruction.rs",
  "        if config_writable {\n            AccountMeta::new(config, false)\n        } else {\n            AccountMeta::new_readonly(config, false)\n        },",
  "        AccountMeta::new(config, false),"),
 ("I2 rotation validator order sorted", "src/solana/instruction.rs",
  "    for v in validators {\n        data.extend_from_slice(v.as_ref());\n    }\n    data.push(threshold);",
  "    let mut sorted: Vec<Pubkey> = validators.to_vec();\n    sorted.sort();\n    for v in &sorted {\n        data.extend_from_slice(v.as_ref());\n    }\n    data.push(threshold);"),
 ("I3 set_paused ignores its argument", "src/solana/instruction.rs",
  "    data.push(u8::from(paused));",
  "    data.push(1);"),
 ("I4 cancel gains a system program", "src/solana/instruction.rs",
  "            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),\n        ],\n        data: anchor_discriminator(\"cancel_validator_rotation\").to_vec(),",
  "            AccountMeta::new_readonly(INSTRUCTIONS_SYSVAR_ID, false),\n            AccountMeta::new_readonly(system_program::id(), false),\n        ],\n        data: anchor_discriminator(\"cancel_validator_rotation\").to_vec(),"),
 ("I5 admin marked writable", "src/solana/instruction.rs",
  "        AccountMeta::new_readonly(*admin, true),\n        AccountMeta::new(bridge_config_pda(program_id).0, false),",
  "        AccountMeta::new(*admin, true),\n        AccountMeta::new(bridge_config_pda(program_id).0, false),"),
 ("I6 governance PDA uses the wrong seed", "src/solana/instruction.rs",
  'pub const SEED_GOVERNANCE_ACTION: &[u8] = b"governance_action";',
  'pub const SEED_GOVERNANCE_ACTION: &[u8] = b"governance-action";'),
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
    a = run("cargo test --lib -- ops::preflight solana::rpc solana::instruction")
    # -p only resolves from the repo root: the relayer is a SEPARATE
    # workspace (ADR-0001). Running it from ROOT silently exits non-zero and
    # every mutant looks "broken", which is how I6 first hid.
    b = run("cargo test -p glc-bridge --test admin_governance_encoding", cwd="/home/reaper/glc-solana-bridge")
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
