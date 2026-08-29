# M4 — method

How the numbers in `eval/results/summary.md` were produced, what they cover,
and what they cannot cover. Section citations resolve against
`docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`; `NOTES #n`
against `docs/ref/NOTES.md`.

## Running it

```
go run ./eval                 # 200 latency samples per configuration
go run ./eval -n 1000         # more samples
go run ./eval -out /some/dir  # artifacts elsewhere (default eval/results)
```

One command builds `cmd/wardend`, writes a trust anchor, constructs both
corpora, presents every case to a live proxy over stdio, measures latency at
three depths in three configurations, and writes:

| file | what |
|---|---|
| `corpus.json` | every case as presented: name, corpus, class, invariant, profile, expected decision, expected clause |
| `results.csv`, `results.json` | one row per case: decision, clause cited, the trace's message |
| `latency.csv` | percentiles per configuration and depth |
| `summary.md` | the tables above, generated |
| `corpus-audit.jsonl`, `latency-*.jsonl` | the raw audit records the oracle read |

The `.jsonl` logs and the rebuilt `wardend` are gitignored; the corpora, the
CSV/JSON results and `summary.md` are committed.

`wardend` spawns its upstream as a subprocess, so the harness re-execs itself
in server role (`WARDEN_EVAL_ROLE=server`) rather than shipping a second
binary. The upstream is `internal/testserver`, in-process, answering in tens
of microseconds.

## The corpora

### Benign — 19 cases, and why they are independent

Every benign case is a delegation an orchestrator would actually perform and a
call warden SHOULD permit. A denial in this corpus is a finding to
investigate, never a case to relabel.

Independence from the adversarial corpus is structural rather than a matter of
discipline. Benign chains are built exclusively through `(*chain).derive`,
which mints through `aat.Deriver` — §6, warden's own issuer path. Adversarial
chains are built through `(*chain).forge`, which signs a claim map directly and
never touches the issuer. The two share the trust anchor and the wire encoder
and nothing else; no benign case is an adversarial case with a field put back.

The cases were written from the delegation patterns, not from the verifier:
direct invocation, tool-set narrowing over one and three hops, TTL shortening,
each of the §4.5 narrowing directions that has a wider and a narrower form
(`one_of` → `exact`, `range` → narrower `range`, `subset` → smaller `subset`,
`contains` → more required, `wildcard` → anything, `not_one_of` → more
excluded), open-world grants invoked with arbitrary arguments, closed-world
grants invoked at their boundary, and same-scope links (§6) which are permits
carrying `chain.same_scope` in the audit record, checked as such.

### Adversarial — 58 cases

Written from the threat model: T1–T6 in §8, and the invariants I1–I6. Each
case is named for the rule it attacks and carries the clause that should
refuse it. 54 expect a denial; 4 expect a permit and are the documented
non-blocks below.

### The two profiles

Every case is labelled `conformant` or `warden`:

- **conformant draft-01** — the expected outcome follows from the draft alone.
- **warden profile** — the expected outcome depends on a choice recorded in
  ADR 0001 or in `docs/ref/NOTES.md`, where the draft is silent or ambiguous.
  Rejecting an unrecognized member inside a constraint object (NOTES #3) and
  rejecting an empty `constraints` array outside the one case §3.4 forbids it
  (NOTES #2) are warden's calls, not the draft's.

The block rate is reported for both splits so a reader who disagrees with a
warden-profile choice can read the conformant number alone.

## The oracle

### The decision comes from the audit record

Not from the wire. A denial is observable on the wire as a JSON-RPC error only
when the call carried an id; the notification-bypass case sends a
`tools/call` with no id, so there is no response to read and the audit record
is the only place the decision exists. Reading every case the same way keeps
that case from needing its own oracle.

It also keeps the peer out of the result. `internal/testserver` implements
`echo` and nothing else, so a permitted `search`, `read_file` or `write_file`
comes back as JSON-RPC `-32602 unknown tool`. That code appears in
`results.csv` and is the upstream's answer to a call warden allowed through —
warden's decision on those rows is `permit`, in the audit record, which is what
the false-positive rate counts.

### The join is keyed, and the count is asserted

Records are joined to cases by `audit.Record.Corr` — `"c"+seq`, assigned when
the proxy *reads* a `tools/call`, so it is presentation order by construction
rather than by luck. Positional joins break silently: M1 had exactly that bug,
a pending call registered after the forward with a fast response arriving
first, and one lost record shifts everything after it, so fifty rows read as
findings where there is one.

Three checks run before any case is scored, and each aborts the run with a
diagnostic instead of reporting:

1. the number of emitted records equals the number of calls presented;
2. every `corr` is in `c1..cN` and appears exactly once;
3. the joined record's argument digest matches the digest of the arguments the
   case sent.

The audit file is also removed before each proxy starts: `wardend` opens it
`O_APPEND`, and a file left by an earlier run would arrive as extra records and
trip check 1.

### `want_ref` is the clause, not the code path

Each adversarial case carries the *finest normative clause true of that input*
— what the operator should be told, decided from the draft, not from what
warden currently does. Blocks then partition three ways:

- **correctly attributed** — the trace's ref equals `want_ref`;
- **wrong clause** — the trace cited something else;
- **uncited** — the refusal carried no `core.Denial`, so `decision.deny` fell
  to its stage floor (`§7`, `ARCHITECTURE §3.1`, `ARCHITECTURE §2.4`) and the
  operator is told which stage refused, not which clause.

`Result.Detail` carries the trace's message beside the ref, because a coarse
ref with a precise message is a different defect from a ref that names a rule
not true of the input, and the two are indistinguishable from refs alone.

## Findings: the eight blocks attributed wrongly (M4), and their fix (M4b)

M4's first run blocked 54 of 54 and attributed 46 of them — 85.2%. The eight
misses are recorded below as they were found; M4b fixed all eight and the
current run reads 100% / 100%. Read the diagnosis, not just the number: what
made the eight wrong is the part that generalizes.

All eight stopped the call. None was a security failure; all eight were
failures of SPEC contribution 3, the decision trace.

**Six wrong-clause rows have one cause.** `internal/aat/chain.go:158` wraps
every error out of `verifyThenParse` in `Deny("§7 steps 4a-4b, I1", …)` and
`:227` wraps the root's in `Deny("§7 steps 3a-3b, I1", …)`. Parse-time errors
carry no `Denial` of their own, and `RefOf` returns the innermost one, so the
coarse wrapper's ref is the only ref there is. The operator is told the link
failed its parent-key binding when the signature verified fine.

Within those six, two groups that should not be read alike:

*Coarse but containing* — the ref is wider than the wanted step, the message
names the right rule:

- `i2-terminal-parent-delegates` and `i2-chain-beyond-deployment-max` say
  `del_depth (N) exceeds del_max_depth (M) (§4.3 I2)` in the message text.
  The correct clause is in the sentence and absent from the machine-readable
  field: anything that alerts on `ref` rather than reading the sentence buckets
  an I2 violation as I1.
- `i5-par_hash-omitted-on-derived` says `par_hash MUST be present in derived
  tokens (§3.2 Table 1)` where §7 step 4b5 was wanted. Table 1 is the rule
  4b5 checks.

*Actively false* — the message describes a defect the input does not have.
`Claims.validate` infers root-vs-derived from `del_depth == 0` (token.go:258)
instead of checking Table 1 as a table, so a token with the wrong combination
is told about the row it was inferred into:

- `root-nonzero-del_depth` — a root carrying `del_depth = 3` is classified
  derived and told `par_hash MUST be present in derived tokens`. The defect is
  the non-zero depth (§7 step 3c), and the outer sentence, `root verifies under
  no trust anchor`, is false as well: the root's signature verified.
- `i2-depth-not-incremented` — a child that kept its parent's `del_depth = 0`
  is classified root and told `par_hash MUST be absent in root tokens`. The
  defect — depth not incremented, §7 step 4d, I2 — is never named.
- `root-carries-par_hash` sits between the groups: the inner message is right
  (`par_hash MUST be absent in root tokens`, §3.2 Table 1, where §7 step 3d was
  wanted), and the outer `root verifies under no trust anchor` is not.

**Two uncited rows** are `unrecognized-member-in-constraint` and
`empty-constraints-array`. Both are refused inside `core`'s constraint parser
with a plain error and no `Denial`, so the trace falls to the `§7` floor where
`§3.4` was wanted. The messages are precise and operator-readable; only the
machine-readable ref is missing.

### What M4b changed

The fix mostly *removed* checks. `internal/core/chain.go` already carried every
wanted ref — `§7 step 3c`, `§7 step 4d, I2`, `§7 step 4e, I2` — and never got to
run, because a coarser check upstream answered first with a worse citation.

1. `verifyThenParse` is split. `verifySignature` does §7's algorithm-then-
   signature ordering and keeps the coarse `3a-3b` / `4a-4b` ref, which five
   cases legitimately want. Parsing is now the caller's separate step under its
   own clause: `§7 step 3b` for the root, `§7 steps 4b1-4b5` for a link. A claim
   defect no longer reads as a key-binding failure.
2. `Claims.validate` no longer infers position from `del_depth == 0`. The
   par_hash-presence rule and the `del_depth <= del_max_depth` bound left it
   entirely; §7 asks them where the position is known — steps 3d and 4b5 for
   presence, 4d/4e/4m for depth. The same inference stayed in `Mint`, where it
   is sound: the caller authored those claims, so the two fields cannot disagree
   the way an attacker's can, and warden should not sign what it would deny.
   The derived-`iss` thumbprint-prefix test went too — §7 step 4c compares
   `iss` against the parent holder key's actual thumbprint, which is strictly
   stronger and cites I1 correctly.
3. Seven structural failures in `core`'s constraint parser became
   `Deny("§3.4", …)`. That closed the uncited class, not just the two rows.
4. One corpus case was confounded: `root-carries-par_hash` forged a par_hash
   that was also not base64url, so Table 1's shape rule (position-independent,
   correctly checked at parse) fired before the positional prohibition. The
   forged value is now well-formed; the shape rule keeps its own unit test.
   No expectation was relabelled.

The two toy chain fixtures that widened a constraint *and* added a tool in one
mutation were narrowed for the same reason: `CheckI4` walks a map, so a case
with two violations reports whichever the runtime iterates first.

## Documented non-blocks

Four adversarial cases are permitted by a decision on record, and they are
first-class rows in the summary rather than a footnote: a block rate is only
readable next to what was deliberately left unblocked.

| case | decision |
|---|---|
| `jcs-ambiguous-constraint-literal` | NOTES #7 — RFC 8785 collapses `9007199254740993` and `…92` to the same float64, so a call can differ from the grant in a way §7 step 7f cannot see. warden refuses the ambiguous literal at mint, not at verify. |
| `pop-replay-first-use` | the legitimate use, presented so the replay below is the same bytes |
| `pop-replay-within-skew` | NOTES #9 — §8.5's replay MUST is conditioned on an irreversibility classification the protocol never carries, so warden implements §7 step 7g only. The window is about twice `MAX_IAT_SKEW`, 60 s by default. |
| `unbounded-repetition` | warden has no budget or rate counters (M2b, deferred). T4 is unmitigated by design today; no §3.4 constraint type expresses a call budget. |

## Limits of the measurement

**The benign corpus cannot exercise I1–I4.** `aat.Deriver` runs
`core.CheckLink` before it mints — the same function §7 step 4 runs at verify.
A benign case that would violate I1–I4 cannot be built: it fails at
construction and is reported as `build_err`, never presented. The 0% false
positive rate therefore covers the bind stage, §7 steps 1–3, 4q, 5, 6b and 7,
and not the domain invariants. A legitimate delegation that `CheckLink`
wrongly refuses would appear in this harness as a build failure, not as a
denial — the run reports build failures for exactly that reason, and there were
none.

**Audience binding is unexercised.** The harness never passes `-audience`, so
§7 step 7d never fires. That is warden's default (NOTES #8: the draft delegates
audience binding to deployment policy), so the measurement matches the default
deployment and says nothing about a bound one.

**One trust anchor.** Anchor-set size is not a variable here, by choice: it
would confound the depth measurement, which is what ROADMAP's target is stated
against. §7 step 3b's behaviour with many anchors is untested by this harness.

**The corpus and the code have the same author.** The 100% block rate says
every attack someone thought to write down was stopped. It cannot say anything
about attacks nobody wrote, and the strongest reason to distrust it is that the
person who wrote the checks wrote the tests for them.

**T4 has no denial cases at all** — its only case is the documented non-block.
The `n/a` in that row of the summary is honest and should stay `n/a` until
budget counters exist.

**19 benign cases is small**, hand-written, and not generated. There is no
property-based or fuzzed benign corpus; a false positive that needs an unusual
argument shape to trigger would not be found here.

## Latency method

M1's convention, unchanged so the three milestones compare: nearest-rank
percentiles, `overhead = total − upstream`, microseconds. `upstream` includes
pipe transit both ways, booked to the server's column by convention.

Three configurations at depths 1, 3, 5: `enforcing` (full §7),
`passthrough-bound` (`-passthrough-only`, token present and ignored), and
`passthrough-bare` (no `_meta` at all, depth 0). Latency chains derive with a
changed `exp` at every hop so no link is same-scope, which keeps §6's
same-scope path out of the timing.

**The peer is fast, and that shapes every percentage.** The upstream answers in
tens of microseconds, so relative overhead here is a statement about that peer,
not about warden. The microseconds are the number that transfers to a real
server.

**Depth-3 total p99 is 1.246 ms against ROADMAP's <1 ms target.** That is a
miss. It is better than M2's ~2.1 ms, and the cause named at M2 exit still
holds — every request re-parses and re-canonicalizes every token in the chain,
and a verified chain is immutable — but the target is not met and is not
restated to fit.

## Triaging a benign denial

If a future run denies a benign case, the M0b1 completeness probe is the
triage tool. Two of its numbers matter: 44.9% of rejected `all → all`
constraint pairs had no witness, and 30.5% of all cross-type pairs rejected by
§4.5's default-deny had none. A "no witness" rejection is one where `Subsumes`
refused a pair for which no concrete argument distinguishes the two
constraints — sound, since §4.5 is deliberately conservative, but not
necessary. So: check first whether the denial is a §4.5 default-deny with no
witness. If it is, the case is legitimate and the conservatism is the cause,
and the finding belongs in the granularity discussion (ADR 0001), not in the
verifier.
