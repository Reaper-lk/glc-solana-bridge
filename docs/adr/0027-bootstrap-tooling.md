# ADR-0027: Bootstrap tooling

- Status: **Accepted** (owner decision, 2026-08-01).
- Phase: 7m
- Closes the last implementable launch blocker.

---

## 1. What was missing

Reassessing the launch checklist against the codebase, four instructions had
**no caller outside the program's own test suite**:

| instruction | needed for |
|---|---|
| `initialize` | launch step 3 — creating the bridge |
| `create_wrapped_mint` | launch step 3 — the wrapped GLC mint |
| `transfer_admin` | custody #5 — handing the admin key to a multisig |
| `accept_admin` | the other half of that handover |

There was also no way to read the configuration back, which launch step 3
explicitly requires.

**The bridge could not be stood up with the shipped binaries.** The launch
checklist written in Phase 7j listed step 3 as though it were executable.

## 2. How this was missed

Phases 7i-0, 7i-1 and 7i each found the same class of gap and each verified
against the thing in front of them: incident procedures, then the governance
lifecycle, then the runbooks. None checked **the first operation** — standing
the bridge up — because every phase was reasoning about a bridge that already
existed.

The checklist I wrote in 7j inherited that assumption. Its "verified" column
was honest about what tests covered; its launch-day sequence was not
subjected to the same "does a shipped tool do this?" question the runbooks
were.

## 3. Decision

`glc-admin` gains `initialize`, `create-wrapped-mint`, `show-config`,
`transfer-admin` and `accept-admin`, and `solana::rpc` gains a
`BridgeConfig` decoder.

Design points worth recording:

- **`initialize` refuses a zero timelock and a zero supply cap in the
  client**, before the program does, so an operator gets a sentence rather
  than a constraint error. Neither has a default (owner decision U6).
- **Validator order is echoed back before submission.** It fixes each
  member's bitmask index for the life of the federation; a transposition is
  unrecoverable without a rotation.
- **`create-wrapped-mint` refuses if a mint is already configured**, reading
  the config first, rather than letting the program reject it opaquely. It
  also states that the mint keypair confers nothing afterwards — it is one
  more thing to lose, not an asset to keep.
- **`accept-admin` checks that the configured key *is* the pending admin**
  before submitting, because the natural mistake is running it on the
  outgoing admin's host.

### 3.1 The `Option<Pubkey>` that moves every field after it

`BridgeConfig::pending_admin` is `Option<Pubkey>`: Borsh writes a one-byte
tag, followed by the value **only when present**. Every later field —
including the wrapped mint and the supply ceiling — therefore sits 32 bytes
further along while a handover is in flight.

Decoding from fixed offsets would return wrong values **exactly during an
admin handover**, which is precisely when an operator is running
`show-config` to check. The decoder computes offsets, an invalid tag is an
error rather than a guess, and both layouts are pinned on both sides of the
workspace split.

## 4. Verification

- **Cross-workspace encoding contract** extended to all four instructions and
  to `BridgeConfig`, in the same shape ADR-0022 established: the program's
  tests assert Anchor *generates* the spec, the relayer's assert it
  *produces* it.
- **Real-validator rehearsal.** `rehearsal_rotation.rs` now bootstraps
  through the *shipped* builder rather than a test-local copy, and a second
  rehearsal runs the whole sequence: initialize → read back →
  create the mint → nominate a successor → confirm the outgoing admin still
  governs → accept → confirm the old key no longer does.
- **13 mutants, all killed** (`docs/experiments/phase7m-mutants.py`),
  covering validator ordering, argument order, the mint's signer flag, the
  loader used to derive `ProgramData`, which side signs each handover step,
  and every offset in the config decoder.
- The runbook consistency test **caught the five new commands as
  undocumented** on its first run, which is what it is for.

## 5. Consequences

- The documented launch sequence is executable end to end.
- `docs/runbooks.md` §14 covers bootstrap and the admin handover.
- This is the last item closable by writing code; what remains is owner
  decisions, external audit, real-world rehearsal, and rollout.

## 6. What this ADR does not decide

- Any parameter value — every one is a live security decision (U6).
- Who holds the admin key, or what it is handed to (custody #5).
- When the bridge is launched.
