# Mutation and determinism experiments — status, and a standing caveat

These harnesses are hand-applied: each entry rewrites one guard into a
weakened form and checks that the test suite fails. A mutant that **survives**
is a guard nothing tests.

`docs/release-readiness-v1.0.md` §9 and `docs/remaining-before-launch.md` §2
describe these as "six mutation suites with every mutant killed". That is true
of the mutants that **ran**. It is not the same claim as "every listed guard
has mutation coverage", and the difference is the subject of this file.

## The failure mode these harnesses have

A mutant is applied by literal string replacement. When the source drifts away
from the string a mutant was written against, the replacement silently does
nothing — and the harness reports the entry as `BROKEN` while its summary
still prints `survived: 0`.

`survived: 0` therefore does **not** mean "every guard is covered". It means
"nothing that was successfully applied survived". A `BROKEN` entry is neither
killed nor survived: it is a guard whose coverage was **asserted and then
quietly lost**, and it looks identical to a passing suite unless someone reads
the per-entry output.

This is the same class of defect the repository keeps finding in itself
(release-readiness §9.1): not bad code, but a check whose fixtures agree with
each other and with nothing else.

## Verified status, 2026-08-03

Run against `ef8fa2e` with `GOLDCOIND_BIN` / `GOLDCOIN_CLI_BIN` pointed at the
official Goldcoin **v0.17.0-beta1** binaries.

### Suites that ran

| suite | killed | survived | broken |
|---|---|---|---|
| `phase7i-mutants` | 9 | 0 | **1** |
| `phase7i0-mutants` | 21 | 0 | **2** |
| `phase7i1-mutants` | 22 | 0 | 0 |
| `phase7k-mutants` | 17 | 0 | 0 |
| `phase7l-mutants` | 16 | 0 | 0 |
| `phase7m-mutants` | 13 | 0 | 0 |
| `token-metadata-mutants` | 15 | 0 | **1** |

### Suites that did not run at all

`phase7e-01-determinism-and-merge`, `phase7e-02-parallel-merge-and-sighash`,
`phase7e-03-cross-node-determinism`, `phase7e-04-signature-ordering` all
aborted with:

```
urllib.error.URLError: <urlopen error [Errno 111] Connection refused>
```

They require a **live Goldcoin node already listening at a hardcoded
endpoint**, which they neither start nor document as a prerequisite. Nothing
in the output distinguishes "these four determinism properties were verified"
from "these four never executed" except the traceback.

### The four guards with no mutation coverage

Each pattern below was checked against the current source independently of the
harness's own report. All four are genuinely absent — the code moved and the
mutants did not:

| id | target | why it did not apply |
|---|---|---|
| `S5` unknown-input check accepts anything | `src/p2p/sweep_view.rs` | pattern not found |
| `P6` input identity check removed | `src/withdrawal/sweep.rs` | pattern not found |
| `U7` relayer update marks metadata read-only | `src/solana/instruction.rs` | pattern not found |
| `H2` invariant emitted even without an indexer | `src/ops/` | did not compile or run |

`S5` and `P6` guard the **sweep** path — the vault-compromise response, which
`runbooks.md` §5 already flags as never rehearsed, and where the one defect a
rehearsal did find (txid byte order) had likewise been agreed-with by
twenty-two unit tests and twenty-three killed mutants.

## Two mechanical problems in the harnesses themselves

- **`ROOT` is hardcoded** to `/home/reaper/glc-solana-bridge/relayer` in all
  seven mutant scripts. They cannot run from a checkout anywhere else without
  editing, which is why nothing in CI runs them.
- **Nothing runs these in CI.** `.github/workflows/` has no job for them, so
  drift between a mutant's pattern and the source it targets is only ever
  discovered by someone running them by hand.

## What this file is not

It is not a repair. Fixing these means rewriting four mutants against the
current source, giving the `phase7e` scripts a node to talk to (or a documented
prerequisite and a non-zero exit that says so), de-hardcoding `ROOT`, and
deciding whether a `BROKEN` entry should fail the run — which it should, since
a mutation harness that reports everything killed for mechanical reasons is
worse than no harness at all, as `phase7i-mutants.py`'s own docstring says
about two earlier traps of exactly this kind.

Until that is done, treat "every mutant killed" as covering the mutants listed
above as **killed**, and nothing else.
