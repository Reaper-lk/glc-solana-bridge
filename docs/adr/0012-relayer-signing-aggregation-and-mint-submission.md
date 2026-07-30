# ADR-0012: Relayer signing, aggregation, and mint submission

- Status: Accepted (owner decision, 2026-07-30)
- Phase: 5

## Context

ADR-0011 left Phase 4 at unsigned canonical claim artifacts in
`ReadyForSignature`. Phase 5's objective: monitor those deposits, load
validator keys, sign the ADR-0010 canonical message, aggregate signatures,
verify threshold client-side, build and submit `mint_wrapped`, wait for
confirmation, and reconcile to `Minted` — idempotently, restart-safely,
retry-safely, never double-minting, and never signing a modified message.

## Decision

**R1 — hand-built instruction encoding.** `solana::instruction` builds the
`mint_wrapped` discriminator (`sha256("global:mint_wrapped")[..8]`), Borsh
args, and all 11 account metas by hand, copied verbatim from the on-chain
`MintWrapped` accounts struct and `constants.rs`. No path dependency on the
on-chain `glc-bridge` crate — this workspace stays genuinely independent of
anchor-lang (ADR-0001).

**R2 — single-process bootstrap topology (test/bootstrap only).** One
relayer process loads and holds every validator's ed25519 keypair
(`signer::load_validator_keypairs`) and signs with all of them itself
(`signer::sign_with_all`). This is explicitly **not** the production
federation design — a real deployment must have each validator hold its
own key on its own infrastructure, exchanging signatures over a network
(`p2p`, still a placeholder). `signer/mod.rs`'s module docs carry this
warning; it must not be deployed beyond a controlled test/bootstrap
environment.

**R3 — explicit commitment, no silent default.** `SolanaConfig::validate`
rejects anything but exactly `"processed"`/`"confirmed"`/`"finalized"` for
the confirmation commitment level — mirrors `glc::config`'s discipline of
never silently defaulting a security-relevant parameter.

**R4 — relayer's own keypair is the fee payer.** The configured Solana
keypair (`submitter`) pays every `mint_wrapped` transaction's fees and the
claim account's rent. It confers no authority — a valid M-of-N proof is
the only authority (ADR-0010, owner decision U7) — so any funded keypair
could serve this role.

**R5 — sequential processing, one transaction per deposit.** Each tick
processes every `ReadyForSignature`/`Submitted` row in turn; no batching.

**Reload-and-recompute signing safeguard.** Immediately before signing,
`Db::verify_and_load_signable_message` — inside one SQLite transaction —
reloads the deposit's live `txid`/`vout`/`amount_atomic`/`recipient` and the
frozen `claim_artifacts` commitment (`protocol_version`/`validator_epoch`/
`program_id`/`wrapped_mint`/stored `canonical_message`/stored
`message_hash`), checks `sha256(stored canonical_message) == stored
message_hash` (self-consistency), recomputes the canonical message from
the reloaded fields, and requires it to be byte-identical to the stored
message. Only the freshly recomputed bytes are ever returned to sign — the
stored blob is never signed directly, even when everything matches.

**`IntegrityHalted`, not `Failed`, on mismatch (owner correction).** The
original proposal transitioned a detected mismatch to `Failed`. The owner
explicitly rejected this: `Failed` covers routine, expected rejections
(malformed binding, below-minimum amount); a message-integrity mismatch
means database corruption, a bug, or tampering, and must never be filed
alongside those or auto-retried. `DepositState::IntegrityHalted` is a
distinct terminal state, reachable only from this one code path, and is
audited via `deposit_state_log` (`reason` set to
`"claim_artifact_self_inconsistent"` or
`"claim_message_recomputed_mismatch"`). It requires manual operator
investigation — nothing in the codebase automatically clears it.

**`IntegrityHalted` is terminal until explicit operator action.** The
orchestrator's tick only ever selects `ReadyForSignature` and `Submitted`
rows, so a halted deposit is structurally never re-entered: it is not
retried on later ticks, not resumed by a process restart, and not re-opened
even if the underlying data is subsequently repaired (an attacker able to
write to the database must not be able to un-halt a deposit by reverting
their own edit). Because the claim-PDA `get_account` is unconditionally the
first statement in `process_one`, an unchanged `get_account` call count
proves `process_one` was never entered — and therefore that
`signer::sign_with_all` was unreachable and no validator signature over any
message was produced. Terminality is per-deposit: a halted row does not
stall the rest of the queue.

**The only exit is `Db::operator_clear_integrity_halt`.** It is called from
no automatic path anywhere in the codebase. It requires a non-empty
`operator_note`, applies only to a deposit actually in `IntegrityHalted`,
and restricts the target to `ReadyForSignature` or `Failed` — never
directly to `Submitted` or `Minted`, so an operator can never hand-place a
deposit into a state that implies a mint occurred. Recovery to
`ReadyForSignature` merely re-admits the deposit to the normal pipeline,
where the reload-and-recompute safeguard runs again from scratch and halts
it straight back if the anomaly persists. The original halt record is never
deleted or rewritten — `deposit_state_log` is append-only, so the anomaly
remains permanently visible alongside the attributed recovery.

**Forensic audit content (schema v3).** A coarse reason string is not
enough to investigate suspected corruption, so an `IntegrityHalted`
transition records, in `deposit_state_log`: the deposit id, the detection
timestamp, the reason, the `expected_message_hash` (the stored commitment),
the `recomputed_message_hash` (what current persisted state actually
produces), and `differing_fields` — the canonical-message field name(s)
that drifted, derived by comparing the recomputed and stored messages at
the ADR-0010 field offsets. `differing_fields` is null when attribution is
not possible (a corrupted stored *hash* means no field drifted; a truncated
stored message has no meaningful offsets). This diff is strictly
diagnostic — nothing in it can influence which bytes get signed.

**Reconciliation is checked first, always.** For every
`ReadyForSignature`/`Submitted` row, `Orchestrator::process_one` checks
whether the claim PDA already exists on-chain *before* attempting anything
else. If it exists, the row is marked `Minted` immediately — no signing, no
submission. Only if it doesn't exist does the pipeline proceed through the
reload-and-recompute safeguard, signing, aggregation, threshold check, and
submission.

**This reconciliation check is the entire idempotency/restart/retry-safety
mechanism**, deliberately reused verbatim for both states:

- *Idempotent / never double-mints*: the claim PDA's on-chain `init`
  constraint permits at most one successful creation per `(txid, vout)`,
  regardless of how many `mint_wrapped` transactions are ever submitted for
  it — client-side reconciliation is a courtesy that avoids wasted
  submissions, not the actual security boundary.
- *Restart-safe*: a crash at any point — before signing, after signing but
  before submission, after submission but before confirmation — is
  recovered identically on the next tick: reconciliation either finds the
  PDA (mark `Minted`) or doesn't (re-sign/resubmit from scratch, per the
  safeguard, which never trusts anything cached).
- *Retry-safe*: a `Submitted` row whose claim PDA doesn't exist yet
  (transaction still in flight, or dropped/expired) is resubmitted every
  tick exactly like a `ReadyForSignature` row. This is safe purely because
  of the on-chain `init` constraint, not because the relayer tracks
  submission status — and is what makes a dropped or expired in-flight
  transaction self-healing rather than stuck forever, at the cost of
  possible duplicate fee spend under slow confirmation (see Consequences).

**Client-side threshold check is a courtesy only.**
`signer::aggregate::count_unique_threshold_signers` mirrors the on-chain
`count_unique_validator_signers` rules against the current `ValidatorSet`
account (fetched fresh every tick, never cached) to avoid wasting a
submission the program would reject anyway. The on-chain verifier remains
the sole security authority regardless of what this check returns.

## Consequences

- A `Submitted` deposit without a confirmed claim PDA yet is resubmitted
  every tick until either it confirms or an operator intervenes — this
  trades a bounded amount of duplicate fee spend (paid by the relayer's own
  `submitter` keypair) for never getting permanently stuck on a dropped or
  expired transaction, without needing a separate expiry-detection
  mechanism or a `get_signature_statuses` call. A future phase could add
  one to reduce the duplicate-fee window, without changing correctness.
- Confirmation is observed *across ticks* via the same reconciliation
  check, not via a blocking wait inside one tick — `send_transaction` is
  fire-and-forget (`skip_preflight: false`, preflight only) and the tick
  loop never blocks waiting for a signature status. This keeps ticks fast
  and reuses one mechanism for both "just submitted" and "restarted mid-
  flight," at the cost of one extra tick's latency to observe a mint that
  confirms quickly.
- Phase 5 never creates the recipient's associated token account for the
  wrapped mint. `mint_wrapped`'s `recipient_token_account` requires it to
  already exist (no `init_if_needed`) — a deposit whose recipient has no
  ATA yet will fail to mint on every tick indefinitely, with no operator
  signal beyond the deposit never leaving `ReadyForSignature`. Ensuring the
  ATA exists ahead of a deposit landing is out of this phase's scope and
  should be tracked as follow-up work (either relayer-side ATA creation, a
  documented operational precondition, or a monitoring signal for
  stuck-in-`ReadyForSignature` deposits).
- `glc::indexer::Indexer` and the new `Orchestrator` each open their own
  SQLite connection to the same database file and run as independent
  `tokio::spawn` tasks (`main.rs`) — `Db::open` now enables WAL journal
  mode and a 5-second busy timeout specifically for this overlap, since a
  single default-mode connection would otherwise risk spurious "database
  is locked" errors under concurrent writes.
- `Indexer::call`/`Orchestrator::call` (and `Indexer::find_fork_point`)
  had to change from `&self` to free functions / `&mut self`: a shared
  `&Indexer`/`&Orchestrator` held across an `.await` requires that type to
  be `Sync`, which neither is (`rusqlite::Connection`'s statement cache
  uses a `RefCell`) — invisible while each ran as a plain awaited future in
  `main`, but a hard compile error once `tokio::spawn` requires the whole
  future to be `Send`.
- `cargo deny check` newly reports two RustSec advisories (`rustls-webpki`
  CRL-parsing panic, `time` RFC 2822 stack exhaustion) and several
  copyleft/non-allow-listed licenses (`MPL-2.0`, `CDLA-Permissive-2.0` via
  `webpki-roots`/`webpki-root-certs`), all transitively forced by
  `solana-client`'s non-optional QUIC/pubsub-websocket sub-crates
  (`solana-quic-client`, `solana-pubsub-client`, `solana-streamer`), which
  `RealSolanaRpc` never actually exercises (it only ever uses plain HTTPS
  JSON-RPC). `solana-client` does not expose a feature flag to drop these.
  This needs an explicit owner decision (documented `deny.toml` exception
  vs. an alternative dependency shape) — not something to resolve
  unilaterally.
