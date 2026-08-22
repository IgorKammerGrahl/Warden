# warden — STATE

Updated: 2026-08-22 (end of M0a pass)

## Current milestone

**M0a — Encoding and crypto.** `internal/aat`: JWT/JWS compact serialization,
Ed25519 sign/verify, the AAT claim struct and its decoder, RFC 8785 JCS
canonicalization. No constraint semantics, no chain verification.

## Done

- Phase 1 docs (SPEC, ARCHITECTURE, ROADMAP rev. 3, ADR 0001) under git.
- AAT draft-01 vendored at `docs/ref/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`.
  **All future section citations resolve against that file, not against
  quotations copied into our own docs.**
- M0a in progress. `internal/aat/jcs` (RFC 8785) and `internal/aat/jws`
  (compact serialization, Ed25519, alg allowlist) are implemented and green.
  `internal/aat` (claims, JWK, PoP) is partially written and does not compile.

## Next 3 tasks

1. **M0b — AAT semantics.** The nine §3.4 core constraint types with `check`,
   §4.5 `subsumes`, the §7 eight-step chain verification algorithm, §5.3 PoP
   verification, and the two property tests (subsumption soundness, chain
   soundness). Gated on M0a's exit criteria, which are met.
2. **Fold the vendored draft back into ADR 0001.** Four recorded issues below
   plus the §10.3.1 finding from the previous pass now resolvable against real
   text rather than against our own quotation.
3. **M1 — MCP proxy passthrough + audit** in log-only mode.

## Open decisions

### Deferred ADR 0001 issues (recorded 2026-08-22, to be fixed in the M2 pass — NOT M0a)

- **ADR §3 must cite draft §8.1.2.** The draft explicitly lists cumulative /
  frequency-of-use control as a threat it does not mitigate, and points to rate
  limiting as a complementary control. Our contribution is therefore "the
  extension registry cannot host the complementary control the draft points to",
  not "we found an overlooked gap". Also cite §8.5 as precedent that
  enforcement-side state is already part of the model.

- **The §10.3.1 criterion-2 relocation (ADR B3) is incomplete.** §3.5.1's *Sound*
  property is itself quantified over argument values. Relocating only §10.3.1
  leaves the contradiction in place. Soundness for invocation-granularity types
  must be restated over counter states: subsumes(Cd,Cp) => for all states S,
  Cd.check(S) implies Cp.check(S).

- **ADR §4 Counter state, obligation 1 is wrong as written.** "Every ancestor's
  counter, one per token on the chain" — tokens carrying no instance of that
  type have no counter. Should read "every ancestor carrying an instance of
  that type".

- **State-loss detection has a hole.** Timer snapshots plus "stale = older than
  the oldest live token's iat" does not detect a crash between snapshots: spend
  since the last snapshot is silently refunded. Either charge durably before
  PERMIT, or state the bounded loss explicitly. Also record single-`wardend`-
  instance as a declared v1 non-goal (in-memory counters are not shared).

### Still open from Phase 1

- **D3 (CEL)** revisited with evidence at M2 exit, per ROADMAP.
- **Whether the draft author agrees the granularity gap is real.** ADR 0001 is
  written to be sendable to `niki@tenuo.ai` largely as-is. Not sent — Igor's call.

## M0a exit criteria

| Criterion | Status |
|---|---|
| Round-trip a signed root token and a signed derived token (mint → serialize → parse → verify signature) | **not met** — tests written (`TestRootRoundTrip`, `TestDerivedChainRoundTrip`), `internal/aat` implementation incomplete |
| Every RFC 8785 test vector passes byte-for-byte | met — `internal/aat/jcs`, 61 subtests, 0 skipped, no vector adjusted |
| `go test -fuzz` clean on decode and JCS, no panics | **not met** — fuzz targets exist (`FuzzCanonicalize`, `jws.FuzzParse`, `aat.FuzzParse`); no `-fuzz` run has been executed yet |

## Conventions in force

- Conventional commits, one logical change per commit.
- New dependency ⇒ one-line justification against the decision ladder in the
  commit that adds it. **M0a added zero dependencies; `go.mod` has no `require`.**
- Any divergence from AAT draft-01 gets an ADR entry.
- STATE.md updated at the end of every session.
