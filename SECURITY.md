# Security policy

## Status

**Phase 0 — scaffold only.** Nothing is deployed, no token exists, no keys
exist, and no code path moves value. Even so, design-level reports (flaws in
the documented architecture, threat model, or ADRs) are welcome now — they
are cheapest to fix before implementation.

## Reporting a vulnerability

- **Private reports only** for anything potentially exploitable:
  use GitHub private vulnerability reporting on this repository
  (<https://github.com/Reaper-lk/glc-solana-bridge/security/advisories/new>).
- Do **not** open public issues for suspected vulnerabilities.
- Include: affected file/component, the scenario in which it matters
  (which phase / deployment state), and reproduction or reasoning.

Response target: acknowledgment within 7 days. No bug bounty exists at this
stage.

## Scope notes for researchers

- The authoritative security documentation is
  [docs/threat-model.md](docs/threat-model.md) (risks, invariants) and
  [docs/custody.md](docs/custody.md) (explicitly unresolved decisions —
  reports that an *open* question is open are not findings).
- Goldcoin Core itself is out of scope here — this repository never modifies
  it; report node vulnerabilities upstream to the Goldcoin project.
- Anything that looks like a real key, secret, or deploy artifact in this
  repository is itself a finding — none should ever exist here.
