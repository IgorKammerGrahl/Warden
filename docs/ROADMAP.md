# warden — Roadmap

Status: **DRAFT — Phase 1 correction pass (rev. 4, 2026-08-23).** D1–D3 resolved,
so no milestone is decision-blocked. Each milestone is independently demoable and
gated on the previous one. Rev. 3 split M0 into **M0a** (encoding + crypto) and
**M0b** (semantics) with a manual gate between them. Rev. 4 records M2's split
into **M2a** (the stateless path, shipped) and **M2b** (enforcement state,
folded into M3); **M1 and M3–M5 keep their identifiers unchanged.**

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
post-M3), relaying every message and denying nothing: it reads the `_meta`
binding (ARCHITECTURE §3.1) when present, records **presence, size and shape
only**, and forwards. **Zero calls to §7 verification — no `Verify`, no
capability check, no PoP check, nowhere in the request path.** Absent or
malformed `_meta` is recorded and forwarded; fail-closed is M2.

**The zero-verification rule is load-bearing, not a shortcut.** M1's latency
numbers are the control M4's enforcement overhead is measured against, so the
M1 request path must contain no authorization decision at all — a `Verify` call
here, even one whose result is discarded, puts Ed25519 work into the baseline
and silently deflates M4's reported overhead. The `-passthrough-only` flag
exists from M1 so the same control can be re-measured on an M2 binary.

- Demo: point an off-the-shelf MCP client at `wardend`, watch
  `wardenctl audit tail` narrate every call — decision `passthrough`, with what
  the binding carried.
- Exit: transparent passthrough (client can't tell — response payloads compared
  byte for byte against calling the server directly); every call audited;
  measured proxy overhead baseline (p50/p99) recorded with its measurement
  convention stated — this number is the M4 control.

## M2 — Enforcement

**Split during execution.** M2 as written below is two milestones' worth of
work: a stateless half that turns the §7 algorithm into a live authorization
decision, and a stateful half — counters, replay sets, revocation — that is
really a question about where enforcement state lives. **M2a shipped; M2b is
folded into M3**, where the four unresolved ADR 0001 state issues are settled
before a second state store is built on an unsettled answer.

### M2a — the stateless path (**done, 2026-08-23**)

Allow/deny on leaf capability claims (closed-world argument checking) + PoP,
the full ARCHITECTURE §3.2 pipeline in `internal/proxy`, fail-closed on every
binding failure, and the `extensions.invocation_constraints` gate rejecting
rather than ignoring a chain that carries the member. Denials reach the client
as JSON-RPC -32001 carrying the stage and the normative ref, and the audit
record carries the same ref. `-trust-anchors` is mandatory to start enforcing;
`-passthrough-only` preserves M1's control path on the same binary.

- Exit, met: a three-token chain authorizes a permitted call end-to-end; an
  out-of-authority call is denied with a client-visible error and an audit
  trace naming the clause; every fail-closed bind path has a test; latency
  reported passthrough vs enforcing at depths 1/3/5 (see STATE.md).
- Found and fixed on the way: a `tools/call` sent as a **notification** has no
  `id` and was therefore invisible to a correlation-based relay — it would have
  been forwarded unverified, and a caller does not need a response for the side
  effect to land.
- Found and raised: RFC 8785 canonicalizes numbers through binary64, so §7 step
  7f cannot distinguish two integers above 2^53 (NOTES.md #7). warden denies
  them at bind.

### M2b — the stateful path (**deferred into M3**)

Static YAML operator policy; stateful `dev.warden/budget` and `dev.warden/rate`
counters with **per-branch accounting** (D5/D11 — leaf and every ancestor
charged atomically on PERMIT); `invocation_constraints` enforced rather than
merely gated; PoP `jti` replay set (§8.5), which needs the per-tool
irreversibility classification the protocol does not carry (NOTES.md #9);
lineage revocation; fail-closed on counter-state loss (D6).

- Demo: same client, a leaf token authorizing `fs.read` with
  `path: {one_of: [...]}` and a `dev.warden/rate` of 10 calls — allowed calls
  pass; the 11th, an `fs.write`, and an `fs.read` with an unnamed extra argument
  are each denied with the failed step/constraint named in the response.
  (The second and third of those three are blocked today; only the counter is
  missing.)
- Exit: T3/T4-style manual scenarios blocked; benign scripted workload runs with
  zero false positives; the two extension types written up against the §10.3.2
  template — as a *proposed* registration under the `invocation_constraints`
  mechanism, not a registration against draft-01's argument-granularity registry
  (ADR 0001); a chain carrying the member is rejected with the gate off and
  enforced with it on, both covered by tests; **D3 (CEL) revisited with evidence** — a scenario the
  core nine can't express *and* a candidate language with decidable containment
  (Appendix C), or the answer stays no.

## M3 — Delegation chains — shipped 2026-08-23 (derivation), split

Parent-derives-child across processes: agent A derives for agent B (B's own
keypair, A never sees B's private key), depth limits enforced structurally by I2.

`aat.Deriver` computes `iss`, `del_depth` and `par_hash` itself rather than
accepting them, so I1, I2's increment and I5 are not fields a caller can get
wrong, and refuses through `core.CheckLink` — the same function §7 step 4 runs at
the enforcement point — so a derivation that would be denied is never signed.

- Demo: 3-hop chain A→B→C; C's capability is the intersection down the chain.
- Exit, met: a chain minted here verifies through the M2 proxy end to end
  (`TestDerivedChainE2EPermits`); a subchain cannot be re-parented even between
  siblings holding equal authority, because §6 step 7 hashes the parent's JWS
  Signing Input (`TestDerivedTokenCannotBeReparented`); every I1–I6 violation is
  refused at mint and the corresponding forged token is denied at verify
  (`TestForgedLeafIsDeniedAtVerify`); a same-scope derivation permits and is
  flagged on the audit record's `chain.same_scope`.

**Dropped: lineage revocation.** It was scoped before §8.9 was read. The draft
puts per-token revocation outside the specification, names short lifetimes and
trust anchor rotation as what a deployment gets instead, and defers
lineage-scoped cascading revocation to "a companion document" that does not
exist. Building it would have meant inventing a private protocol under the
draft's vocabulary. What shipped instead is `-max-token-lifetime` (§4.4, was a
hardcoded 90 days). The unmet half of §8.9 — rotating the anchor set without a
restart — is NOTES.md #10, and needs its own design pass: it is a live mutation
of the trust root in front of the authorization decision, not a flag.

**Still open, unchanged:** `wardenctl inspect`. And M2b, deferred again for the
reason it was deferred the first time — `invocation_constraints`, budget, rate,
counters and stateful replay tracking all sit on the four unresolved ADR 0001
state issues, and those are a spec question before they are an implementation.

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

**Plus prefix presentation** (`docs/ref/NOTES.md` #6): any prefix of a valid chain
is a valid chain, so a holder who obtains a downstream chain and truncates it to a
prefix whose PoP key they control is authorized at that prefix's wider capability
set. The scenario exists to demonstrate that PoP is the *only* thing stopping it.

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

**The depth-3 target is currently missed by about 2x.** M2a measured p99 ≈ 2.1 ms
added at depth 3 with nothing optimized; a CPU profile puts ~44% in Ed25519
verification and most of the rest in JSON parsing and JCS canonicalization, both
linear in depth. Warden re-parses and re-canonicalizes every token on every
request and a verified chain is immutable, so a verification cache is the obvious
first move — deliberately not built in M2a, because it is a cache keyed by
attacker-supplied bytes sitting in front of the authorization decision, and that
needs designing rather than adding. Either the cache lands before M4 or the
target is restated against measured evidence; it is not carried forward as an
aspiration.

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
