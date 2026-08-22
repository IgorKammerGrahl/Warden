# warden — Architecture

Status: **DRAFT — Phase 1 correction pass (rev. 3, 2026-08-03). D1–D3 RESOLVED;
D5 revised; D10, D11 added.** Rev. 3 withdraws the `"*"` pseudo-argument placement
(§2.4, ADR 0001) and settles sibling-budget semantics.

warden implements `draft-niyikiza-oauth-attenuating-agent-tokens-01` (AAT), pinned.
Section references of the form "§N" below refer to **that draft**; warden's own
sections are written "ARCHITECTURE §N".

---

## 1. Overview

```
   root issuer                 derives offline              derives offline
  (wardenctl,     root AAT      (library)      AAT d=1       (library)     AAT d=2
   holds root  ─────────────►  Agent A  ───────────────►  Agent B  ──────────────►  …
   private key)                   │                          │
                                  │  tools/call              │  tools/call
                                  │  + chain [root..leaf]    │  + chain
                                  │  + PoP JWT (per call)    │  + PoP JWT
                                  ▼                          ▼
              ┌──────────────────────────────────────────────────────────────┐
              │            wardend  —  AAT enforcement point                 │
              │  trust anchors (PUBLIC keys only)  +  enforcement state      │
              │                                                              │
              │  §7 chain verification (8 steps, verify-before-parse)        │
              │    → closed-world leaf arg check  → PoP verify (I6)          │
              │    → warden extension constraints (budget / rate: stateful)  │
              │    → operator static policy (YAML)                           │
              │    → ALLOW: forward to upstream MCP server                   │
              │    → DENY : MCP error + decision trace                       │
              │  every decision → audit log (contribution 3)                 │
              └────────────────────────────┬─────────────────────────────────┘
                                           ▼
                                 upstream MCP server(s)
```

Three hard rules:

1. **Derivation is offline.** A parent agent derives a child token locally with the
   library — no round trip to `wardend` or to any AS (§6). This is the core
   differentiator vs. RFC 8693.
2. **Verification is offline too.** `wardend` verifies a chain using only the
   configured **trust anchor public keys** — no network calls, no shared secret,
   no access to any private key (§7). This is the property that makes the
   multi-party case work: an enforcement point can verify a chain minted in
   another trust domain. It is also the reason D1 changed (ARCHITECTURE §2.3).
3. **State is local and fails closed.** Budget counters, rate windows, PoP replay
   `jti` set, and chain-lineage revocation live only in `wardend`. These are
   warden additions, not AAT (gap (b)/(e)); everything AAT specifies verifies
   without them.

`wardend` is *an* enforcement point, not *the* verifier. v1 runs one; nothing in
the token model assumes that.

## 2. Token model — AAT draft-01

### 2.1 Structure and semantics (normative source: §3, §4, §6, §7)

A token is a **signed JWT**. A chain is an ordered array `[root, …, leaf]`; the
leaf is the token whose capabilities are evaluated, and whose holder signs a fresh
PoP JWT per invocation. There are no separate delegation/execution token types —
role is chain position (§3.1).

Claims we carry (§3.2): `jti` (UUIDv7), `iss`, `iat`, `exp`, `cnf.jwk` (holder
public key), `del_depth`, `del_max_depth`, `par_hash` (absent on root, required on
derived), `authorization_details`. **Ed25519 / `EdDSA` only** in v1 — it is the
one algorithm §3.2 makes mandatory, it is `crypto/ed25519` in stdlib, and a
single-algorithm allowlist is the cheapest possible defence against §8.13
algorithm confusion.

Capability claims are an RFC 9396 RAR profile: one `authorization_details` entry
with `type: "attenuating_agent_token"` and a `tools` map from tool identifier to
a map of argument name → constraint (§3.3).

`derive(parent, …)` produces a child that is checked structurally against I1–I6:

| Invariant | Check | Notes for us |
|---|---|---|
| I1 delegation authority | `child.iss == jwk_thumbprint_uri(parent.cnf.jwk)` | RFC 9278 URI over an RFC 7638 SHA-256 thumbprint; offline, no lookup |
| I2 depth | `child.del_depth == parent.del_depth+1`, `≤ parent.del_max_depth`, `≤ child.del_max_depth`, `≤ MAX_DELEGATION_DEPTH`; `child.del_max_depth ≤ parent.del_max_depth` | `del_max_depth` is an **absolute ceiling, not a remaining count** — the old `depth` caveat design was wrong about this |
| I3 TTL | `child.exp ≤ parent.exp`, `child.iat ≥ parent.iat`, `iat ≤ now+MAX_IAT_SKEW`, `exp ≤ iat+MAX_TOKEN_LIFETIME` | orthogonal to capability: equal capability + shorter TTL is still valid attenuation |
| I4 capability | tool set ⊆ parent's; per-argument `subsumes` (§4.5); closed-world key-set preservation | the whole of ARCHITECTURE §2.2 |
| I5 linkage | `child.par_hash == base64url-nopad(SHA-256(parent JWS Signing Input))` | binds to one parent **instance**, defeating chain re-parenting |
| I6 PoP | leaf holder signs the invocation | ARCHITECTURE §3.2 |

**Implementation limits** (§4.3.1, Appendix B.5) — configurable, defaults as
recommended: `MAX_TOKEN_SIZE` 64 KiB, `MAX_STACK_SIZE` 256 KiB,
`MAX_CONSTRAINT_DEPTH` 32, `MAX_DELEGATION_DEPTH` 8 (v1: linear chains, per B.4
guidance to size it to the topology), `MAX_IAT_SKEW` 30 s, `MAX_TOKEN_LIFETIME`
1 h (far below the 90-day ceiling; per B.7, TTL is our primary revocation
substitute).

### 2.2 Constraint vocabulary — the nine core types, adopted verbatim

**D3 resolved: adopt §3.4's vocabulary; extend, never invent.** The previously
proposed closed set of six custom caveats (`tools`/`args`/`ttl`/`depth`/`budget`/
`rate`) is **deleted**. Tools, TTL, and depth are token claims in AAT, not
constraints; argument constraints are the nine types below; budget and rate become
registered extensions (ARCHITECTURE §2.4).

`exact`, `range`, `one_of`, `not_one_of`, `contains`, `subset`, `wildcard`, `all`,
`any` — `check` predicates per §3.4 and subsumption **exactly** per §4.5, including:

- per-type rules (e.g. `range`: child bounds inside parent's, and a child may
  tighten `min_inclusive: true → false` but never the reverse; a child bound
  cannot be absent where the parent has one);
- cross-type rules (e.g. a derived `exact` subsuming a parent `one_of`/`range`/
  `wildcard` when its value satisfies the parent's predicate);
- `all`: **backtracking one-to-one matching** — every parent clause must be
  subsumed by a *distinct* child clause (§4.5 gives the pseudocode; a maximum-matching
  algorithm such as Hopcroft–Karp is permitted, and the search space is bounded by
  the parent clause count);
- `any`: every child clause must be subsumed by at least one parent clause;
- **every (parent type, child type) pair not explicitly permitted MUST be
  rejected.** Default-deny on the subsumption matrix, not default-allow.

Two rules from the draft that are **mandatory, not options**, and that the pipeline
in ARCHITECTURE §3 must reflect:

- **Closed-world semantics (§3.3).** If a tool's constraint map is non-empty, an
  argument not named in it is rejected, and a named-but-absent argument is
  rejected. There is no "optional constraint". To permit an unrestricted argument,
  the issuer must write an explicit `wildcard`. An empty map `{}` means the tool is
  authorized with no argument restrictions (open world) — and a child may then
  introduce keys, transitioning open→closed.
- **Fail-closed on unknown constraint types (§3.4, §8.8).** An unrecognized
  `constraint_type` ⇒ DENY. Not skip, not warn. Applies to registered extensions we
  have not implemented, too (§3.5.2).

Where §4.5 is internally ambiguous (see SPEC §5.1), warden takes the **narrower**
reading and records the divergence. Conservative incompleteness is explicitly
permitted (§3.5.1); unsoundness is not.

### 2.3 D1 — RESOLVED: implement AAT draft-01; the custom HMAC macaroon chain is dropped

The rev. 1 tradeoff table (custom HMAC chain vs. Biscuit vs. AAT) is deleted. It
was decided on a false premise — that AAT was "a token format with no enforcement."
It is a complete protocol (SPEC §3.5). Rationale for the resolution, in the order
that matters:

- **Technical (decisive).** An HMAC macaroon chain requires the verifier to hold
  the root secret. That breaks the exact case that motivates this project: an
  enforcement point verifying a chain minted in *another trust domain*. Symmetric
  crypto also cannot express per-holder key binding, so proof of possession is
  unavailable — §8.13 forbids HS\* for AAT signatures for precisely this reason.
  AAT's Ed25519 + trust-anchor model verifies offline with public keys only.
  Rev. 1 called single-verifier "a v1 simplification"; it was actually a
  self-inflicted ceiling on the thesis's own multi-party premise.
- **Strategic.** warden becomes an *independent implementation of an emerging
  standard* rather than the author of a bespoke format. For the thesis this is
  strictly better: there is a formed, normative baseline to implement against and
  compare to, and RQ1 becomes a real result (independent soundness evidence for
  §4.5, where the author's own verification is still in progress per Appendix E.2)
  instead of "our format satisfies our invariant." For BuilderHub it is credibility:
  standards-track alignment beats a homegrown token.
- **Practical.** The cost is smaller than it looks. `crypto/ed25519`,
  `crypto/sha256`, `encoding/json`, `encoding/base64` are all stdlib. The JOSE
  subset we need is *one* algorithm, compact serialization only, no JWE, no key
  agreement, no JWKS fetching: sign = `ed25519.Sign(key, signingInput)`,
  verify = `ed25519.Verify(pub, signingInput, sig)`, where `signingInput =
  b64url(header) + "." + b64url(payload)`. Per the decision ladder that is rungs
  2–5, so we **implement it directly rather than pulling `go-jose` or `golang-jwt`** —
  a general JOSE library brings an algorithm zoo we would immediately have to
  allowlist away, and §8.13 makes "the library decides which algorithms exist" an
  active liability. JCS (RFC 8785) for PoP `hta` is ~100 lines and is the one place
  to be careful (see ARCHITECTURE §3.2).
  Revisit only if we need a second algorithm or a real JWKS story.

Consequence: `internal/core` no longer owns a wire format. Ownership of the
*publishable* artifact moves to the four contributions in SPEC §2.

### 2.4 warden extension constraint types (contribution 2)

> **Rev. 3 change.** The `"*"` pseudo-argument placement recorded in rev. 2 is
> **withdrawn**: it is broken by construction. §7 step 6b denies any invocation
> missing an argument named in the constraint map, and no invocation ever carries an
> argument literally named `"*"`, so the key denies *every* call to that tool at any
> conformant enforcement point — and §7 step 4 p2's key-set preservation pins it
> into every descendant token. Full analysis, the refutation of the two alternative
> placements, and the proposed replacement are in
> **[ADR 0001](adr/0001-invocation-granularity-constraints.md)**. Read that before
> touching this section.

Budget and rate are **cumulative controls over a sequence of invocations**, and
AAT's extension registry is indexed by argument name at every layer. They therefore
do not fit anywhere in draft-01. warden carries them in a proposed
`invocation_constraints` member of the `attenuating_agent_token` entry, sibling to
`tools`:

```jsonc
{
  "type": "attenuating_agent_token",
  "tools": { "transfer_funds": { "amount": { "constraint_type": "range", "max": 5000 } } },
  "invocation_constraints": {
    "dev.warden/budget": { "max": 10000, "currency": "USD" },
    "dev.warden/rate":   { "max_calls": 50, "window_seconds": 3600 }
  }
}
```

Keys are registered type names (at most one instance per type); values are
evaluated **once per invocation**, after the §7 step 6b capability check and before
PERMIT, independently of which tool was called. An absent member means no
invocation-level constraints. §3.5.1's obligations (decidable, sound,
deterministic `subsumes`; exhaustive cross-type rules) and §3.5.2's fail-closed
rule apply unchanged, per type rather than per argument key.

**Subsumption for the member as a whole is monotone, not exact-match:** the child
MUST carry every type the parent carries (removing one drops a conjunct and widens
authority ⇒ DENY), MAY add types the parent lacks (adding a conjunct narrows ⇒
ordinary attenuation), and for shared types must satisfy that type's `subsumes`.
This deliberately differs from §7 step 4 p2's exact key-set equality, which is
correct for arguments only because closed-world semantics make both addition and
removal escape the parent's permitted set. Invocation constraints have no
caller-supplied value being adjudicated, so monotone addition is sound. The reasoning
is in ADR 0001 §4.

**This is off by default.** With `extensions.invocation_constraints` disabled,
`wardend` **rejects** a chain carrying the member rather than ignoring it. Enabling
it asserts that every enforcement point in the deployment is warden — chains
carrying it are not interoperable with a draft-01-only peer (SPEC §5.3). Nothing
else in warden diverges; in particular the §7 step 6b closed-world check is
implemented exactly as written, with no reserved keys and no special cases.

**The design point that makes this legal:** subsumption stays **structural and
offline** — it compares the numbers in two tokens and nothing else. Only
*enforcement* is stateful. So I4 is satisfied by the same per-link structural check
as every core type, and offline chain verification is preserved: a verifier with no
counters can still decide that a chain is well-attenuated; it just cannot decide
whether the budget is *already spent*.

| | `dev.warden/budget` | `dev.warden/rate` |
|---|---|---|
| Members | `max` (integer, currency minor units), `currency` (ISO 4217) | `max_calls` (integer), `window_seconds` (integer) |
| `check()` | Stateful, no argument. Let `spent` = cumulative charge on the counters this invocation is accountable to (see *Counter keying*, below). Passes iff `spent + cost(invocation) ≤ max` for every one of them. `cost` comes from the operator's per-tool cost table (config), never from the agent | Stateful, no argument. Passes iff calls in the trailing `window_seconds` on every accountable counter `< max_calls` |
| `subsumes(Cd, Cp)` | **Structural.** `Cd.currency == Cp.currency ∧ Cd.max ≤ Cp.max`. Differing currency ⇒ false (no FX at verification time — nondeterministic, violates §3.5.1) | **Structural.** `Cd.max_calls ≤ Cp.max_calls ∧ Cd.window_seconds ≥ Cp.window_seconds`. A longer window with no more calls is strictly weaker or equal; any other combination ⇒ false, conservatively |
| Decidable | O(1) integer comparison | O(1) integer comparison |
| Sound | `spent + c ≤ Cd.max ≤ Cp.max` ⇒ parent predicate holds for the same `spent` | fewer calls permitted over a window at least as long ⇒ parent predicate holds |
| Deterministic | integer comparison, no locale, no floats — amounts are minor units | integer comparison |
| Cross-type vs. core | **Only `range` interoperates**, one direction: a derived `range` with `max ≤ Cp.max` and no lower bound below 0 subsumes a parent `dev.warden/budget`… *rejected for v1.* A `range` is stateless and would silently drop the cumulative check. **Every cross-type pair is declared invalid**, per §3.5.1's requirement to enumerate: parent `budget` accepts only child `budget`; parent `rate` only child `rate` | as left |

#### Counter keying: per-branch allocation (D10)

Rev. 2 keyed counters by **chain lineage** (root `jti`), one pool per lineage. That
is underspecified for siblings, and the underspecification is not benign. Two
sub-agents derived from the same parent, each carrying `max: 50` under a parent's
`max: 100`, would share a single 50-unit pool: whichever spends first starves the
other, and the parent's grant of 100 becomes unreachable by construction.

The two candidates, and the choice:

| | (a) shared lineage pool | (b) per-branch allocation |
|---|---|---|
| Counter key | root `jti` | the token's own `jti`, at every level |
| Charge on invocation | one counter | every ancestor's counter and the leaf's, atomically, in one transaction |
| Sibling behaviour | first spender starves the rest | each branch spends its own grant; parent's balance still caps the sum |
| Parent grant of 100 split 50/50 | at most 50 total ever spent | up to 100 total, ≤ 50 per branch |
| Live counters | one per lineage | one per live token |

**Decision: (b), per-branch allocation.** (a) is not conservative-but-safe; it is
semantically wrong. A parent that grants 100 and delegates 50 twice has authorized
100 units of spend, and (a) delivers 50. The over-restriction is invisible at
verification time, appears only as a runtime denial, and would land in M4 as a
false positive with no explanation available from the token chain — precisely the
"unexplained" category that is worst for the paper. (b) costs a walk up the chain
bounded by `MAX_DELEGATION_DEPTH` (8), charging each ancestor's counter in a single
atomic transaction so a partial charge cannot leave counters skewed; if any
ancestor's check fails, the whole invocation is denied and nothing is charged.
Budget amplification — the thing (a) existed to prevent — is still prevented,
because every ancestor is charged: a child cannot mint its way to more spend than
its parent's counter allows.

The obvious objection to (b) is counter-set growth: one counter per token rather
than one per lineage. The answer is `exp`. Every AAT carries a mandatory expiry
(warden: 1 h, well under `MAX_TOKEN_LIFETIME`), so a counter is collectable once
its token expires and the live set is bounded by the number of live tokens, not by
history. The same keying applies to `dev.warden/rate`.

**Consequence for D5:** the `min()` rule is **deleted**, not moved. Structural
subsumption already guarantees `child.max ≤ parent.max` at every link, so `min()`
over a verified chain is just `leaf.max` — it was redundant under (a) too. Under
(b) the ancestor caps are enforced by charging the ancestors' counters, which is
where that check belongs.

M4's benign corpus MUST include a sibling-delegation scenario (one parent, two
children, concurrent spend against overlapping grants) so this behaviour appears in
the false-positive numbers rather than hiding in them (ROADMAP M4).

**Where the state lives, and what happens when it is lost.** Counters live in
`wardend` memory, keyed as above, snapshotted to a single local file on
a timer and on clean shutdown. **On state loss — cold start with no snapshot, a
corrupt snapshot, or a snapshot older than the oldest live token's `iat` —
`wardend` refuses every invocation carrying a `dev.warden/*` constraint until an
operator explicitly resets the counters (`wardenctl budget reset`). Fail closed.**
Restarting a guardrail must never be a way to refill a budget. Invocations with no
stateful constraint are unaffected: their verification is fully offline.

## 3. MCP proxy (`wardend`) and the transport binding

- Speaks MCP on both sides: downstream (agents connect to it as if it were the
  tool server) and upstream (it is a client of the real MCP servers). Config maps
  upstream servers; tool lists are namespaced (`github:issues.create`). Namespaced
  names are the AAT tool identifiers; §3.3.1 requires **exact string matching** —
  no case folding, no Unicode or URI normalization, no alias resolution — so the
  namespacing scheme must be applied identically at mint time and at call time.

### 3.1 D2 — RESOLVED: normative MCP transport binding (contribution 1)

§1 of the draft leaves transport undefined and deployment-specific. This section is
warden's binding, and it is written to be citable as a contribution rather than as
an implementation detail. **v1 is stdio-first.**

**Placement.** The chain and the PoP JWT travel in the `_meta` object of the
`tools/call` **request params**, under the reserved prefix `dev.warden/`:

```jsonc
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": {
    "name": "github:issues.create",
    "arguments": { "repo": "igorkg/warden", "title": "…" },
    "_meta": {
      "dev.warden/chain": ["<root JWT>", "<d1 JWT>", "<leaf JWT>"],
      "dev.warden/pop":   "<PoP JWT>",
      "dev.warden/spec":  "draft-niyikiza-oauth-attenuating-agent-tokens-01"
    }
  }
}
```

**Serialization.**
- `dev.warden/chain` is a **JSON array of compact-serialization JWT strings, in
  root-to-leaf order**. Array, not a delimiter-joined string: JSON gives us the
  framing for free (ladder rung 2), and a delimiter invites the classic
  splitting-mismatch bug. Order is normative and is *not* re-derivable from the
  tokens alone in an adversarial setting — a verifier MUST NOT sort or reorder;
  §7 step 5 (`len(chain) == leaf.del_depth + 1`) plus the per-link `par_hash`
  checks are what actually pin the order.
- `dev.warden/pop` is a single compact JWT string (§5.2), signed by the leaf
  holder key, with `aat_id` = leaf `jti`, `aat_tool` = the `params.name` value
  **byte-identical** to what is being called, `aat_aud` = this enforcement point's
  configured identifier (warden **requires** `aat_aud`; §8.5 only SHOULDs it, but
  making it mandatory costs nothing and removes cross-enforcement-point replay),
  and `hta` = the `params.arguments` map.
- `dev.warden/spec` is the pinned draft identifier. Present so that an audit record
  and a future interop failure are attributable to a spec revision (SPEC §5.1
  mitigation 1). A value that is not the pinned string ⇒ deny. When any token in
  the chain carries an `invocation_constraints` member (§2.4), the value gains the
  suffix `+dev.warden.invocation_constraints`, marking the chain as a warden-profile
  chain rather than a conformant draft-01 one. Out-of-band labelling like this is
  only possible because warden defined the transport binding; the signal does not
  generalize, which is itself part of the finding in ADR 0001.

**`hta` canonicalization.** §7 step 7f compares the JCS-canonical (RFC 8785) form
of `pop.hta` against the JCS-canonical form of `params.arguments`; the enforcement
point canonicalizes both sides itself and compares **byte sequences**. It never
compares parsed structures and never trusts the sender's encoding. This is the
single subtlest part of the binding — JCS number formatting and string escaping are
where independent implementations diverge — so it gets its own table-driven test
suite in M0 and is the first thing to check in any interop test.

**Size limits.** `MAX_TOKEN_SIZE` 64 KiB per token, `MAX_STACK_SIZE` 256 KiB per
chain (§4.3.1), enforced on the raw encoded bytes **before** any parsing (§7 step
2). Since `_meta` rides inside a JSON-RPC message body, the whole message is also
capped (default 1 MiB) and oversize messages are rejected at the framing layer.
Note Appendix B.5's warning that chains routinely exceed the 4–8 KiB header limits
of common proxies — a body-carried `_meta` binding sidesteps that class of failure
entirely, which is an argument for this binding beyond stdio compatibility.

**Absent or malformed `_meta` ⇒ fail closed.** No `dev.warden/chain`, no
`dev.warden/pop`, an empty array, a non-string element, a mismatched `spec`, or
`_meta` absent entirely ⇒ **DENY**, with a decision trace naming the binding
failure. There is no unauthenticated path through the proxy and no "bearer
fallback." (M1 is the sole exception: log-only mode records the would-be denial and
forwards, which is why M1 is explicitly labelled non-enforcing.)

**Why `_meta` and not `Authorization: Bearer`.** `_meta` is per-call (a chain and a
PoP are meaningful only per invocation — the PoP signs `aat_tool` and `hta`),
works on stdio where there are no headers, survives intermediate MCP hops as
passthrough metadata, and does not collide with MCP's own OAuth 2.1 layer, which
authorizes the *client↔server session* and is orthogonal to delegation. A bearer
header is per-connection, HTTP-only, and would force us to re-send the chain
per-call anyway.

**Deferred to post-M3: HTTP/SSE binding.** The same three `_meta` keys carry
unchanged over streamable HTTP, since they live in the JSON-RPC body. Implementing
it is then a transport concern, not a protocol concern — which is precisely the
evidence that the binding is *general* rather than stdio-specific. Framed that way
in the paper; **not a v1 requirement**, and not a milestone gate.

### 3.2 Enforcement pipeline (per `tools/call`)

An interceptor chain, matching the direction of MCP's Interceptors WG. Ordering is
not ours to choose where §7 fixes it — in particular **verify before parse** (§7:
signature checked before claims are deserialized into application structures) and
**PoP only after full chain verification** (§5.3: a valid PoP against an unverified
chain MUST NOT authorize).

1. **Bind** — extract `_meta` keys, check `spec`, enforce size limits on raw bytes,
   minimal-parse `jti` per token for duplicate/cycle detection (§7 steps 1–2).
2. **Verify chain** — §7 steps 3–5: `alg` allowlist per token (EdDSA only), root
   against a configured trust anchor, then per link I1 (issuer ≡ parent thumbprint),
   I2 (depth), I3 (TTL), I5 (`par_hash`), I4 (tool-set ⊆ and per-argument
   subsumption, `MAX_CONSTRAINT_DEPTH` checked first), then
   `len(chain) == leaf.del_depth + 1`.
3. **Leaf capability check** — §7 step 6: tool present in the leaf's `tools` map;
   **closed-world** argument check (unknown arg ⇒ deny; constrained-but-absent arg
   ⇒ deny); every present argument satisfies its constraint. Unknown
   `constraint_type` ⇒ deny.
4. **PoP** — §7 step 7: signature under leaf `cnf.jwk`, `aat_id` ≡ leaf `jti`,
   `aat_aud` ≡ us, `aat_tool` ≡ requested tool (exact string), JCS `hta` ≡ JCS
   arguments, `iat` within ±30 s, **and `jti` unseen** (§8.5 requires stateful
   replay tracking for non-idempotent tools; warden applies it to all tools —
   cheaper than maintaining an idempotency classification we would get wrong).
5. **warden stateful extensions** — the `invocation_constraints` member (§2.4).
   Gate first: if any token in the chain carries the member and
   `extensions.invocation_constraints` is disabled, **deny** — warden never ignores
   it. When enabled, `dev.warden/budget` and `dev.warden/rate` are evaluated once
   for the invocation against every accountable counter (leaf and ancestors, D10),
   charged atomically on PERMIT only. Chain-lineage revocation is checked here
   (§8.9 is out of AAT scope; this is a warden deployment mechanism).
6. **Operator static policy** — ARCHITECTURE §5, last because it is the deployment's
   backstop over an already-valid chain.
7. **Forward** to the upstream MCP server, or **deny**.

First failure short-circuits; every stage appends to the decision trace. Deny = MCP
error response carrying a warden error code plus the failed invariant/step/constraint
(machine-readable), so the calling agent can adapt rather than retry blindly. Care:
the error must name *which* check failed without leaking constraint values the
caller was never shown — the trace in the audit log is detailed, the wire error is
coded.

M1 ships this pipeline in log-only mode (evaluate everything, record, forward).

## 4. Delegation API

- Derivation is a **library call** (§6), plus `wardenctl derive` for humans/tests:
  the parent holds its own private key, derives the child locally, and hands the
  *chain* to the child agent out-of-band (spawn env/args, message payload — the
  agent framework's business). The child generates its own keypair and gives the
  parent only its public key, which the parent sets as `child.cnf.jwk`. **A private
  key never crosses a delegation boundary**; §3.2 forbids private key material in
  `cnf` and §7 steps 3l/4b2 make an enforcement point reject a token that contains
  it.
- **Root issuance.** v1 does not run an OAuth AS. `wardenctl mint` acts as a local
  root issuer holding the trust anchor private key: it takes the requesting agent's
  public key (§3.7.2's `req_cnf` in spirit, without the token endpoint), sets
  `del_depth: 0`, `del_max_depth`, TTL, and the granted `authorization_details`.
  §3.7's `/token` endpoint profile and `aat_issuer` metadata are **out of scope for
  v1** and noted as the obvious production path.
- `wardend` admin API (local socket): revoke a chain lineage
  (`wardenctl revoke <root-jti>` — invalidates a token and its descendants, the
  lineage-scoped model §8.9 sketches), inspect (`wardenctl inspect` pretty-prints a
  chain: per-link depth, TTL, and the effective intersected capability at the leaf),
  reset stateful counters, tail the audit log.
- Lineage key = root `jti`. Revocation list is in-memory + a single persisted file,
  checked at pipeline stage 5.

## 5. Policy language

Two layers with distinct owners:

1. **Token capability claims** (per-delegation, minted by agents) — AAT
   `authorization_details`, using the nine core constraint types plus registered
   warden extensions (ARCHITECTURE §2.2, §2.4). Not a language; a typed,
   registry-governed vocabulary. This is what makes monotonicity structurally
   checkable rather than a property of an evaluated program.
2. **Static operator policy** (per-deployment, written by a human) — YAML,
   evaluated at pipeline stage 6 over an already-valid chain: default allow/deny
   per tool, deployment-wide argument constraints, the per-tool **cost table** that
   `dev.warden/budget` charges against, and deployment-wide budget/rate ceilings.
   **Reuses the same nine constraint types** — one `check` implementation, one set
   of property tests, one audit vocabulary. An operator constraint is not part of
   any chain and is never subsumption-checked; it is a backstop, and a denial from
   this layer is tagged distinctly in the trace so it is never confused with an
   attenuation failure.

The rev. 1 custom arg vocabulary (`eq`, `in`, `prefix`, `regex`, `max_len`,
`url_host_in`) is **deleted** — superseded by §3.4. Two notes on what that costs:
`prefix` and `url_host_in` were doing real work for exfiltration control (SPEC T3)
and have no core equivalent, since §3.4 deliberately excludes path/URI matchers as
normalization-dependent. Both are therefore **candidate extension registrations**
(`dev.warden/path_containment` — §3.5.3 already gives a conforming worked example
for exactly this — and `dev.warden/url_host`), each owing the same three properties
as budget and rate. Deferred until M2/M4 shows a scenario the core nine cannot
express; `one_of` over an explicit host list covers the M5 demo.

### 5.1 D3 — RESOLVED: adopt the draft vocabulary; CEL stays deferred

No custom constraint types are invented. Extension is the only growth path, and it
goes through the §3.5.1 obligations (decidable, sound, deterministic `subsumes`;
exhaustive cross-type rules) — which is a meaningfully higher bar than "add a
struct," and is the point.

CEL remains deferred. The reference for revisiting it is now **Appendix C**: a
policy language is admissible as an extension type only if the registration defines
the token encoding of the policy *and* a sound, deterministic procedure for deciding
that a derived policy is no less restrictive than its parent. Appendix C is blunt
that deciding *authorization* is not sufficient — containment is the hard part, and
`cel-go` gives us evaluation, not containment. Cedar is named as an example of a
language with analyzable containment. **Revisit after M2, with evidence**: a
concrete scenario the core nine cannot express, and a candidate language whose
containment analysis is decidable. Absent both, the answer stays no.

## 6. Audit log (`internal/audit`)

AAT specifies no audit format (gap (c)); this is contribution 3 and the artifact
that makes an M4 denial explainable rather than merely counted.

- Append-only JSONL, one record per decision:
  `{ts, spec_version, decision, request{tool, args_digest},
  chain{root_jti, leaf_jti, depth, max_depth}, pop{jti, aud},
  trace[{stage, ref, outcome, detail}], budget_state, latency_us}`.
- `trace[].ref` is the **normative citation** for what fired: an invariant
  (`I4`), a verification step (`§7.6b`), a constraint (`tools.read_file.path`
  with its `constraint_type`), or a warden layer (`ext:dev.warden/budget`,
  `policy:deny_tool`). This is what makes the trace a decision *explanation* — it
  points at a clause in a public specification, not at a line in our code.
- `args_digest` not raw args by default (args can contain secrets/PII); raw-args
  logging is an explicit config flag.
- Written via a buffered async writer; audit failure ⇒ deny-by-default
  (fail-closed) — a guardrail that doesn't log is worse than none for the RQ3
  measurements.
- Hash-chaining for tamper evidence: deferred to M4 if the paper needs it.
- `wardenctl audit tail|grep` renders records human-readable ("DENY
  github:issues.create — §7.6b closed-world: argument `labels` is not named in the
  leaf token's constraint map for this tool").

## 7. Repository layout (opsagent conventions)

```
cmd/wardend/        daemon entrypoint
cmd/wardenctl/      CLI entrypoint
internal/aat/       AAT draft-01: JWT/JWS encode+decode, Ed25519, JCS, claims,
                    derive, the §7 verification algorithm — the ONLY package that
                    knows the wire format exists. Exports SpecVersion.
internal/core/      domain: capability, constraint, check, subsumes, chain,
                    decision — no I/O, no wire format, no deps
internal/enforce/   proxy, interceptor pipeline, stateful counters, extensions
internal/audit/     decision-trace writer + readers
api/                admin API + config schema
docs/               SPEC, ARCHITECTURE, ROADMAP, ADRs (incl. extension registrations)
```

**Format isolation** (SPEC §5.1 mitigation 2) is a **package boundary, not a Go
interface.** `internal/aat` is the only importer of JOSE concerns; `core` speaks
domain types. One implementation does not get an interface — that is a factory for
one product, and if draft-02 forces a change we can extract an interface at the
moment a second implementation actually exists. The isolation that matters is
"which package has to be rewritten," and a package boundary delivers exactly that
for zero code.

Dependency rule: `core` and `aat` import stdlib only. `enforce`/`audit` import
both. `cmd/*` wires everything. Candidate external deps, each justified when
reached: property-testing lib (`pgregory.net/rapid` — dev-only, M0), YAML parser
(M2). **No JOSE library** — see ARCHITECTURE §2.3. **No CBOR** — Appendix D's
CWT profile is explicitly deferred by the draft itself and the reference
implementation's CBOR form is non-interoperable, so JWT/JWS is the only encoding
worth implementing. MCP protocol: implement the narrow slice we proxy
(`initialize`, `tools/list`, `tools/call`) over JSON-RPC 2.0 with stdlib
`encoding/json` rather than pulling an SDK — revisit if the slice grows.

## 8. Design decisions summary

| # | Decision | Choice | Alternatives rejected (why) |
|---|---|---|---|
| D1 | Token substrate | **RESOLVED: implement AAT draft-01** (Ed25519 JWT chain, §7 verification), pinned; JOSE subset hand-rolled on stdlib | Custom HMAC macaroon chain (verifier needs the root secret ⇒ breaks cross-trust-domain verification, no PoP possible, and we'd own the crypto design); Biscuit (Datalog containment isn't structurally checkable, no delegation-chain claims — draft App. A.4); a JOSE library (algorithm zoo we'd immediately allowlist away; §8.13 makes that a liability) |
| D2 | Token attachment / transport | **RESOLVED: `_meta["dev.warden/chain"|"…/pop"|"…/spec"]` per call, stdio-first**; absent ⇒ deny | Bearer header (per-connection, HTTP-only, collides with MCP OAuth, and Appendix B.5 warns chains blow past proxy header limits); HTTP/SSE binding **deferred post-M3** as evidence of generality |
| D3 | Constraint vocabulary + policy expressions | **RESOLVED: the nine §3.4 core types verbatim, §4.5 subsumption exactly**; growth only via §3.5 registered extensions; CEL deferred to post-M2 against Appendix C | A custom closed set of 6 caveats (reinvents a normative vocabulary, forfeits interop and the comparison baseline); CEL/Rego now (containment undecidable ⇒ can't satisfy §3.5.1) |
| D4 | Verification locus | Verification is **offline and public-key** (any holder of the trust anchor); v1 runs a **single enforcement point** only because stateful extensions + revocation + PoP replay state are local | Multi-enforcement-point v1 (would need the consistency model §8.5 declines to specify) — now a v2 concern rather than a crypto impossibility |
| D5 | Stateful extension accounting | **REVISED (rev. 3): per-branch allocation.** Counters keyed by each token's own `jti`; an invocation charges the leaf's counter *and every ancestor's*, atomically, on PERMIT only. The `min()` rule is **deleted** — structural subsumption already forces `child.max ≤ parent.max`, so `min()` over a verified chain is just `leaf.max`. See D10 | Rev. 2's single lineage-keyed pool (siblings starve each other and a parent's grant becomes unreachable — §2.4); fully independent per-token budgets with no ancestor charge (child minting would amplify spend) |
| D6 | Failure mode | Fail closed everywhere: verify error, unknown constraint type (§3.4 mandatory), missing `_meta`, audit write failure, **counter-state loss** ⇒ deny | Fail open (indefensible for a guardrail; and for unknown constraint types the draft forbids it outright) |
| D7 | MCP layer | Proxy in front of servers | SDK/library in agents (unenforceable vs. a malicious agent), server-side plugin (requires modifying every server) |
| D8 | Signature algorithm | **Ed25519 / `EdDSA` only**, single-entry allowlist | The RFC 9449 algorithm set (§8.13 RECOMMENDED): every extra algorithm is confusion surface; §3.2 makes Ed25519 the one MUST, so a one-entry allowlist is both conformant and minimal |
| D9 | Root issuance | `wardenctl mint` as a local root issuer holding the trust anchor private key | §3.7 OAuth token-endpoint profile with `req_cnf` + `aat_issuer` metadata (production path; needs an AS we don't have — out of scope v1) |
| D10 | Placement of cumulative controls | **RESOLVED (rev. 3): a proposed `invocation_constraints` member** sibling to `tools`, with a *monotone* set rule (child MUST keep every parent type, MAY add) rather than §7 step 4 p2's exact key-set equality. Off by default; a chain carrying it is **rejected** when disabled, never ignored. ADR 0001 | The `"*"` pseudo-argument key (denies every invocation — §7 step 6b; **withdrawn**); a top-level JWT claim (§3.4: peers MUST ignore ⇒ silent vanish); a separate `authorization_details` entry type (§3.3: same); piggybacking on a real argument key (breaks §10.3.1 criterion 2, entangles with key-set preservation, corrupts the audit trace) |
| D11 | Counter keying under sibling delegation | **Per-branch (D5 revised).** Recommended and adopted over the shared lineage pool because the shared pool makes a parent's grant unreachable and manufactures unexplainable M4 false positives; growth is bounded by token `exp` | Shared lineage pool keyed by root `jti` (rev. 2) |
