# warden — Roadmap

Status: **DRAFT — Phase 1 correction pass (rev. 3, 2026-08-03).** D1–D3 resolved,
so no milestone is decision-blocked. Each milestone is independently demoable and
gated on the previous one. Rev. 3 splits M0 into **M0a** (encoding + crypto) and
**M0b** (semantics) with a manual gate between them; **M1–M5 keep their
identifiers unchanged.**

---

## M0a — Encoding and crypto

`internal/aat`, bottom half only: JWT/JWS compact serialization (hand-rolled JOSE
subset, single algorithm), Ed25519 sign/verify, the claim struct and its decoder,
and **RFC 8785 JCS canonicalization**. No constraint semantics, no chain
verification.

- JCS is verified **byte-for-byte against the RFC's own test vectors**, not against
  our own expectations.
- Decoder fuzzing (`go test -fuzz`) on the JWT and JSON paths.
- **Exit:** round-trip a signed token (mint → serialize → parse → verify
  signature); every RFC 8785 vector green; fuzz targets clean.

**Why this is its own milestone.** JCS is where independent implementations of a
canonicalization-dependent protocol diverge — number formatting, string escaping,
key ordering — and a JCS bug does not announce itself as a JCS bug; it surfaces as
a PoP verification failure, which looks identical to a semantics bug. Isolating it
behind vectors means a later interop failure against another AAT implementation is
unambiguously attributable, and it means M0b is never debugging canonicalization
and subsumption at the same time. This split also keeps each milestone inside one
execution pass.

**Manual gate between M0a and M0b.** M0a's exit criteria are checked before M0b
starts; M0b does not begin on the same pass.

## M0b — AAT semantics (the correctness core)

`internal/aat` top half + `internal/core`: mint (local root issuer) / derive /
verify — the nine core constraint types with §3.4 `check` and §4.5 `subsumes`, the
§7 eight-step chain verification algorithm, and §5 PoP built on M0a's JCS. Warden
extension types (`dev.warden/budget`, `dev.warden/rate`) ship their `subsumes` and
the `invocation_constraints` monotone set rule here (ADR 0001); their stateful
`check` lands in M2.

- TDD, table-driven tests per constraint type and per verification step. The §4.5
  cross-type subsumption matrix is a table, and every unlisted pair asserts *reject*.
- **Property 1 — subsumption soundness (the one that matters):**
  ```
  ∀ (Cp, Cd) generated constraint trees, ∀ argument values v:
      subsumes(Cd, Cp) == true  ⟹  ( Cd.check(v) ⟹ Cp.check(v) )
  ```
  Generators (`pgregory.net/rapid`) produce nested trees up to
  `MAX_CONSTRAINT_DEPTH`, and value generators are **drawn from the constraints
  themselves** (boundary values of `range`, members and non-members of `one_of`,
  etc.) — uniform random values would almost never hit the interesting cases.
  **Conservative incompleteness is acceptable** per §3.5.1: a `false` from
  `subsumes` on a semantically-subsuming pair is recorded, not failed. **A `true`
  on a non-subsuming pair is the highest-severity bug class in this project** and
  the test is never skipped, weakened, or marked flaky.
- **Property 2 — chain soundness:** no sequence of valid derivations yields a leaf
  authorizing an invocation the root would deny. Generate a random root, a random
  valid derivation sequence, and a random invocation; if the verified leaf permits
  it, the root must permit it too.
- Plus: tamper (any byte of any token) ⇒ verify fails; re-parenting a subchain
  fails on `par_hash` (I5); `alg: none` and HS256-signed tokens rejected (§8.13);
  duplicate `jti` in a chain rejected; depth/TTL only narrow.
- **The gap demonstration (SPEC §7 criterion 5a):** a test asserting that a
  constraint placed under a reserved pseudo-argument key denies *every* invocation
  of its tool under our unmodified §7 step 6b — the mechanical evidence behind
  ADR 0001, kept as a regression guard against anyone "fixing" the closed-world
  check.
- Demo: `wardenctl mint | derive | inspect | verify` round trip in a shell,
  including a PoP-carrying invocation check.
- **Exit:** mint / derive / verify a chain end-to-end **including PoP**, with both
  properties passing across configured runs; cross-type matrix complete;
  `invocation_constraints` subsumption (monotone set rule + per-type rules) covered
  by Property 1's generators.

## M1 — MCP proxy passthrough + audit

`wardend` fronts one upstream MCP server over **stdio** (HTTP/SSE deferred
post-M3), full enforcement pipeline running in **log-only** mode: reads the
`_meta` binding (ARCHITECTURE §3.1) when present, runs §7 verification and the
capability/PoP checks, records the decision trace, forwards regardless.

- Demo: point an off-the-shelf MCP client at `wardend`, watch
  `wardenctl audit tail` narrate every call with would-be decisions.
- Exit: transparent passthrough (client can't tell); every call audited;
  measured proxy overhead baseline (p50/p99) recorded — this number is the
  M4 control.

## M2 — Enforcement

Flip the pipeline live: allow/deny on leaf capability claims (closed-world
argument checking) + PoP + static YAML operator policy; stateful
`dev.warden/budget` and `dev.warden/rate` counters with **per-branch accounting**
(D5/D11 — leaf and every ancestor charged atomically on PERMIT); the
`extensions.invocation_constraints` gate, off by default, rejecting rather than
ignoring a chain that carries the member; PoP `jti` replay set; lineage revocation;
fail-closed everywhere including counter-state loss (D6).

- Demo: same client, a leaf token authorizing `fs.read` with
  `path: {one_of: [...]}` and a `dev.warden/rate` of 10 calls — allowed calls
  pass; the 11th, an `fs.write`, and an `fs.read` with an unnamed extra argument
  are each denied with the failed step/constraint named in the response.
- Exit: T3/T4-style manual scenarios blocked; benign scripted workload runs with
  zero false positives; the two extension types written up against the §10.3.2
  template — as a *proposed* registration under the `invocation_constraints`
  mechanism, not a registration against draft-01's argument-granularity registry
  (ADR 0001); a chain carrying the member is rejected with the gate off and
  enforced with it on, both covered by tests; **D3 (CEL) revisited with evidence** — a scenario the
  core nine can't express *and* a candidate language with decidable containment
  (Appendix C), or the answer stays no.

## M3 — Delegation chains

Parent-derives-child across processes: agent A derives for agent B (B's own
keypair, A never sees B's private key), depth limits enforced structurally by I2,
lineage revocation, `wardenctl inspect` renders the full chain and the effective
leaf authority.

- Demo: 3-hop chain A→B→C; C's capability is the intersection down the chain;
  revoking the root lineage kills B's and C's mid-run.
- Exit: depth cannot be bypassed by re-deriving or by re-parenting a subchain
  (I2 + I5); lineage accounting holds under concurrent children (`-race`).

## M4 — Eval harness (the paper's data)

`eval/` harness driving adversarial + benign scenario suites against a live
`wardend`: confused deputy (T1), delegation escalation (T2), injection-driven
exfiltration (T3), budget/rate abuse (T4), PoP replay and expiry (T5), algorithm
confusion / verifier bypass (T6).

**Scenario coverage is invariant-driven, not just tool-misuse-driven:** the suite
must contain at least one attempted violation of **each of I1–I6** — forge a child
`iss` that isn't the parent's thumbprint (I1); exceed or raise `del_max_depth`
(I2); extend `exp` past the parent's (I3); widen a constraint, add a tool, drop a
constrained argument key (I4); splice or re-parent a chain (I5); present a valid
chain with someone else's PoP, a replayed PoP, or a mismatched `hta` (I6) — plus
the §7 mechanical bypasses: `alg: none`, HS256 confusion, duplicate `jti`, oversize
chain, over-deep constraint tree, unknown constraint type.

**The benign corpus must contain a sibling-delegation scenario:** one parent
grants a budget, derives two children with overlapping sub-grants, and both spend
concurrently. This is the case per-branch allocation (D11) exists to get right, and
it must show up in the false-positive numbers rather than hiding in them — under
the rejected shared-pool design it would have produced denials with no explanation
recoverable from the token chain.

- Metrics: block rate per threat class **and per invariant**, false-positive rate
  on a benign corpus, **conformant-mode and warden-profile numbers reported
  separately** (SPEC §5.3), added latency p50/p99 vs. the M1 baseline broken out by
  chain depth (Ed25519 verify cost is linear in depth); results emitted as
  CSV/JSON + a generated summary table for the paper.
- Exit: 100% block on out-of-authority calls and on every I1–I6 violation attempt;
  FP rate and latency reported (target p99 < 1 ms on the stateless path at depth 3);
  numbers reproducible with one command (`go run ./eval`).

## M5 — Demo

Two toy Go agents: A derives a constrained research task token for B (library
derivation, `_meta` binding per ARCHITECTURE §3.1); B legitimately uses its granted
tools, then attempts out-of-scope calls (different tool, host outside the `one_of`
allowlist, over budget) — warden blocks each with a readable audit trail citing the
clause that fired. Scripted, reproducible, and recordable for the TCC defense /
BuilderHub pitch.

- Exit: `make demo` (or `go run ./demo`) runs end-to-end unattended; README
  walks a stranger through it in < 5 minutes.

## Cross-cutting (every milestone)

- STATE.md at repo root updated each session (current milestone, done, next 3,
  open decisions).
- Conventional commits, one logical change per commit.
- New dependency ⇒ one-line justification against the decision ladder in the
  commit that adds it.
- Any divergence from AAT draft-01 — a narrower reading of an ambiguous rule, a
  placement choice, an unimplemented SHOULD — gets an ADR entry. The pinned spec
  version (`aat.SpecVersion`) is emitted in every audit record; if draft-02 lands,
  the response is a documented delta and a port/stay decision, not a silent
  upgrade (SPEC §5.1).
